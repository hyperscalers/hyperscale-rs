//! Typed column family API — compile-time key/value type safety for RocksDB operations.
//!
//! Each column family is a zero-sized struct implementing [`TypedCf`], which declares
//! the key type, value type, and their encodings. The [`DbCodec`] trait abstracts
//! encode/decode so the same type can use different encodings in different CFs.

use hyperscale_types::BlockHeight;
use rocksdb::{ColumnFamily, WriteBatch};
use std::marker::PhantomData;

// ─── Codec trait ──────────────────────────────────────────────────────────────

/// Codec for encoding/decoding typed values to/from RocksDB byte representations.
pub(crate) trait DbCodec<T> {
    fn encode_to(&self, value: &T, buf: &mut Vec<u8>);
    fn decode(&self, bytes: &[u8]) -> T;

    /// Convenience wrapper that allocates a new Vec.
    fn encode(&self, value: &T) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode_to(value, &mut buf);
        buf
    }
}

// ─── Codec implementations ───────────────────────────────────────────────────

/// SBOR encode/decode. Covers most types in the codebase.
pub(crate) struct SborCodec<T>(PhantomData<T>);

impl<T> Default for SborCodec<T> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<T> DbCodec<T> for SborCodec<T>
where
    T: sbor::prelude::BasicEncode + sbor::prelude::BasicDecode,
{
    fn encode_to(&self, value: &T, buf: &mut Vec<u8>) {
        // basic_encode returns a Vec; append it to buf.
        let encoded = sbor::basic_encode(value).expect("SBOR encoding must succeed");
        buf.extend_from_slice(&encoded);
    }

    fn decode(&self, bytes: &[u8]) -> T {
        sbor::basic_decode(bytes).expect("SBOR decoding must succeed")
    }
}

/// Big-endian u64 codec for heights, versions, etc.
/// Preserves lexicographic ordering in RocksDB.
#[derive(Default)]
pub(crate) struct BeU64Codec;

impl DbCodec<u64> for BeU64Codec {
    fn encode_to(&self, value: &u64, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&value.to_be_bytes());
    }

    fn decode(&self, bytes: &[u8]) -> u64 {
        u64::from_be_bytes(bytes.try_into().expect("u64 key must be 8 bytes"))
    }
}

/// 32-byte hash codec.
#[derive(Default)]
pub(crate) struct HashCodec;

impl DbCodec<hyperscale_types::Hash> for HashCodec {
    fn encode_to(&self, value: &hyperscale_types::Hash, buf: &mut Vec<u8>) {
        buf.extend_from_slice(value.as_bytes());
    }

    fn decode(&self, bytes: &[u8]) -> hyperscale_types::Hash {
        hyperscale_types::Hash::from_hash_bytes(bytes)
    }
}

/// Raw passthrough — value is already `Vec<u8>`.
#[derive(Default)]
pub(crate) struct RawCodec;

impl DbCodec<Vec<u8>> for RawCodec {
    fn encode_to(&self, value: &Vec<u8>, buf: &mut Vec<u8>) {
        buf.extend_from_slice(value);
    }

    fn decode(&self, bytes: &[u8]) -> Vec<u8> {
        bytes.to_vec()
    }
}

/// JMT node key codec — wraps the existing `encode_key` function.
#[derive(Default)]
pub(crate) struct JmtKeyCodec;

impl DbCodec<crate::jmt_stored::StoredNodeKey> for JmtKeyCodec {
    fn encode_to(&self, value: &crate::jmt_stored::StoredNodeKey, buf: &mut Vec<u8>) {
        let encoded = crate::jmt_stored::encode_key(value);
        buf.extend_from_slice(&encoded);
    }

    fn decode(&self, _bytes: &[u8]) -> crate::jmt_stored::StoredNodeKey {
        // JMT keys are only encoded for writes/lookups, never decoded from raw bytes
        // in our codebase (the decode path goes through SBOR for the node values).
        unimplemented!("JMT key decoding not needed — keys are write-only in RocksDB")
    }
}

// ─── TypedCf trait ────────────────────────────────────────────────────────────

/// Trait for typed column family definitions.
///
/// Each CF is a zero-sized struct that declares the key/value types and their
/// codecs. This is the single source of truth for "what lives in this CF and
/// how it's encoded."
pub(crate) trait TypedCf {
    /// CF name — must match the string used in RocksDbConfig.
    /// Not read at runtime by typed helpers (they use [`handle`](Self::handle)),
    /// but serves as documentation and is used by `ALL_COLUMN_FAMILIES`.
    #[allow(dead_code)]
    const NAME: &'static str;

    /// Key type stored in this CF.
    type Key;
    /// Value type stored in this CF.
    type Value;

    /// Codec for encoding/decoding keys.
    type KeyCodec: DbCodec<Self::Key> + Default + 'static;
    /// Codec for encoding/decoding values.
    type ValueCodec: DbCodec<Self::Value> + Default + 'static;

    /// Extract this CF's handle from the resolved handles struct.
    ///
    /// Each implementation is a single field access — the compiler verifies
    /// the mapping at build time, so there's no runtime string dispatch.
    fn handle<'a>(cf: &crate::column_families::CfHandles<'a>) -> &'a rocksdb::ColumnFamily;
}

// ─── ReadableStore trait ─────────────────────────────────────────────────────

/// Abstraction over RocksDB `DB` and `Snapshot` for typed reads.
///
/// Both `DB` and `Snapshot` support the same `get_cf` / `multi_get_cf` operations
/// but don't share a trait in the `rocksdb` crate. This trait bridges that gap
/// so typed read functions work with either backend.
pub(crate) trait ReadableStore {
    fn raw_get_cf(&self, cf: &ColumnFamily, key: &[u8]) -> Option<Vec<u8>>;
    fn raw_multi_get_cf(&self, keys: Vec<(&ColumnFamily, Vec<u8>)>) -> Vec<Option<Vec<u8>>>;
    /// Read from the default column family (no CF handle needed).
    fn raw_get(&self, key: &[u8]) -> Option<Vec<u8>>;
}

impl ReadableStore for rocksdb::DB {
    fn raw_get_cf(&self, cf: &ColumnFamily, key: &[u8]) -> Option<Vec<u8>> {
        self.get_cf(cf, key).expect("BFT CRITICAL: read failed")
    }

    fn raw_multi_get_cf(&self, keys: Vec<(&ColumnFamily, Vec<u8>)>) -> Vec<Option<Vec<u8>>> {
        let refs: Vec<_> = keys.iter().map(|(cf, k)| (*cf, k.as_slice())).collect();
        self.multi_get_cf(refs)
            .into_iter()
            .map(|r| r.expect("BFT CRITICAL: read failed"))
            .collect()
    }

    fn raw_get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.get(key).expect("BFT CRITICAL: read failed")
    }
}

impl ReadableStore for rocksdb::Snapshot<'_> {
    fn raw_get_cf(&self, cf: &ColumnFamily, key: &[u8]) -> Option<Vec<u8>> {
        self.get_cf(cf, key)
            .expect("BFT CRITICAL: snapshot read failed")
    }

    fn raw_multi_get_cf(&self, keys: Vec<(&ColumnFamily, Vec<u8>)>) -> Vec<Option<Vec<u8>>> {
        let refs: Vec<_> = keys.iter().map(|(cf, k)| (*cf, k.as_slice())).collect();
        self.multi_get_cf(refs)
            .into_iter()
            .map(|r| r.expect("BFT CRITICAL: snapshot read failed"))
            .collect()
    }

    fn raw_get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.get(key).expect("BFT CRITICAL: snapshot read failed")
    }
}

// ─── Typed free functions ────────────────────────────────────────────────────
//
// These work with any ReadableStore (DB or Snapshot) and any TypedCf.
// The RocksDbStorage methods become thin wrappers over these.

/// Typed get from any readable store.
pub(crate) fn get<CF: TypedCf>(
    store: &impl ReadableStore,
    cf: &ColumnFamily,
    key: &CF::Key,
) -> Option<CF::Value> {
    let key_bytes = CF::KeyCodec::default().encode(key);
    store
        .raw_get_cf(cf, &key_bytes)
        .map(|bytes| CF::ValueCodec::default().decode(&bytes))
}

/// Typed multi-get from any readable store.
pub(crate) fn multi_get<CF: TypedCf>(
    store: &impl ReadableStore,
    cf: &ColumnFamily,
    keys: &[CF::Key],
) -> Vec<Option<CF::Value>> {
    let codec = CF::KeyCodec::default();
    let key_bytes: Vec<_> = keys.iter().map(|k| (cf, codec.encode(k))).collect();
    let value_codec = CF::ValueCodec::default();
    store
        .raw_multi_get_cf(key_bytes)
        .into_iter()
        .map(|opt| opt.map(|bytes| value_codec.decode(&bytes)))
        .collect()
}

/// Typed put into a WriteBatch.
pub(crate) fn batch_put<CF: TypedCf>(
    batch: &mut WriteBatch,
    cf: &ColumnFamily,
    key: &CF::Key,
    value: &CF::Value,
) {
    let key_bytes = CF::KeyCodec::default().encode(key);
    let value_bytes = CF::ValueCodec::default().encode(value);
    batch.put_cf(cf, &key_bytes, &value_bytes);
}

/// Typed put into a WriteBatch, using pre-serialized value bytes if available.
pub(crate) fn batch_put_raw<CF: TypedCf>(
    batch: &mut WriteBatch,
    cf: &ColumnFamily,
    key: &CF::Key,
    value: &CF::Value,
    raw_value: Option<&[u8]>,
) {
    let key_bytes = CF::KeyCodec::default().encode(key);
    match raw_value {
        Some(bytes) => batch.put_cf(cf, &key_bytes, bytes),
        None => {
            let value_bytes = CF::ValueCodec::default().encode(value);
            batch.put_cf(cf, &key_bytes, &value_bytes);
        }
    }
}

/// Typed delete in a WriteBatch.
pub(crate) fn batch_delete<CF: TypedCf>(batch: &mut WriteBatch, cf: &ColumnFamily, key: &CF::Key) {
    let key_bytes = CF::KeyCodec::default().encode(key);
    batch.delete_cf(cf, &key_bytes);
}

// ─── Typed iteration ─────────────────────────────────────────────────────────
//
// These wrap RocksDB's raw iterators with compile-time key/value decoding.
// Both `DB` and `Snapshot` produce the same `DBRawIteratorWithThreadMode<'_, DB>`
// type, so these functions work with either backend.

/// Typed full-scan iterator over a column family.
///
/// Iterates all entries from the beginning, decoding each key/value through
/// the CF's codecs. Use for small or bounded CFs (votes, stale JMT nodes).
pub(crate) fn iter_all<'a, CF: TypedCf>(
    db: &'a rocksdb::DB,
    cf: &ColumnFamily,
) -> impl Iterator<Item = (CF::Key, CF::Value)> + 'a {
    let mut iter = db.raw_iterator_cf(cf);
    iter.seek_to_first();
    raw_iter_to_typed::<CF>(iter)
}

/// Typed prefix-scan iterator over a column family.
///
/// Seeks to `prefix` and yields decoded entries until the key leaves the
/// prefix range. The end bound is computed by incrementing the last byte
/// of the prefix (standard RocksDB prefix scan pattern).
pub(crate) fn prefix_iter<'a, CF: TypedCf>(
    db: &'a rocksdb::DB,
    cf: &ColumnFamily,
    prefix: &[u8],
) -> impl Iterator<Item = (CF::Key, CF::Value)> + 'a {
    prefix_iter_from::<CF>(db, cf, prefix, prefix)
}

/// Typed prefix-scan iterator starting from a custom seek position.
///
/// Like [`prefix_iter`], but seeks to `start` instead of the prefix.
/// `start` must be >= `prefix`. The end bound is still `next_prefix(prefix)`.
pub(crate) fn prefix_iter_from<'a, CF: TypedCf>(
    db: &'a rocksdb::DB,
    cf: &ColumnFamily,
    prefix: &[u8],
    start: &[u8],
) -> impl Iterator<Item = (CF::Key, CF::Value)> + 'a {
    let mut iter = db.raw_iterator_cf(cf);
    iter.seek(start);
    let end = next_prefix(prefix);
    bounded_iter_to_typed::<CF>(iter, end)
}

/// Typed prefix-scan iterator over a RocksDB snapshot.
///
/// Same as [`prefix_iter`] but reads from a point-in-time snapshot.
pub(crate) fn prefix_iter_snap<'a, CF: TypedCf>(
    snapshot: &'a rocksdb::Snapshot<'_>,
    cf: &ColumnFamily,
    prefix: &[u8],
) -> impl Iterator<Item = (CF::Key, CF::Value)> + 'a {
    prefix_iter_from_snap::<CF>(snapshot, cf, prefix, prefix)
}

/// Typed prefix-scan iterator over a RocksDB snapshot with custom seek position.
pub(crate) fn prefix_iter_from_snap<'a, CF: TypedCf>(
    snapshot: &'a rocksdb::Snapshot<'_>,
    cf: &ColumnFamily,
    prefix: &[u8],
    start: &[u8],
) -> impl Iterator<Item = (CF::Key, CF::Value)> + 'a {
    let mut iter = snapshot.raw_iterator_cf(cf);
    iter.seek(start);
    let end = next_prefix(prefix);
    bounded_iter_to_typed::<CF>(iter, end)
}

/// Convert a raw iterator (already seeked) into a typed iterator that yields
/// all remaining entries.
fn raw_iter_to_typed<'a, CF: TypedCf>(
    mut iter: rocksdb::DBRawIteratorWithThreadMode<'a, rocksdb::DB>,
) -> impl Iterator<Item = (CF::Key, CF::Value)> + 'a {
    let key_codec = CF::KeyCodec::default();
    let value_codec = CF::ValueCodec::default();
    let mut done = false;

    std::iter::from_fn(move || {
        if done {
            return None;
        }
        if iter.valid() {
            let key = key_codec.decode(iter.key()?);
            let value = value_codec.decode(iter.value()?);
            iter.next();
            Some((key, value))
        } else {
            done = true;
            if let Err(e) = iter.status() {
                panic!("BFT CRITICAL: RocksDB iterator error: {e}");
            }
            None
        }
    })
}

/// Convert a raw iterator (already seeked) into a typed iterator bounded by
/// an exclusive end key. `None` end means unbounded (iterate to end).
fn bounded_iter_to_typed<'a, CF: TypedCf>(
    mut iter: rocksdb::DBRawIteratorWithThreadMode<'a, rocksdb::DB>,
    end: Option<Vec<u8>>,
) -> impl Iterator<Item = (CF::Key, CF::Value)> + 'a {
    let key_codec = CF::KeyCodec::default();
    let value_codec = CF::ValueCodec::default();
    let mut done = false;

    std::iter::from_fn(move || {
        if done {
            return None;
        }
        if iter.valid() {
            let raw_key = iter.key()?;
            // Check end bound
            if let Some(ref end) = end {
                if raw_key >= end.as_slice() {
                    done = true;
                    return None;
                }
            }
            let key = key_codec.decode(raw_key);
            let value = value_codec.decode(iter.value()?);
            iter.next();
            Some((key, value))
        } else {
            done = true;
            if let Err(e) = iter.status() {
                panic!("BFT CRITICAL: RocksDB iterator error: {e}");
            }
            None
        }
    })
}

/// Increment a byte prefix to produce the exclusive end bound for a range scan.
///
/// Returns `None` if the prefix is all `0xFF` bytes (no valid exclusive upper bound).
fn next_prefix(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut next = prefix.to_vec();
    for i in (0..next.len()).rev() {
        if next[i] < 255 {
            next[i] += 1;
            return Some(next);
        }
        next[i] = 0;
    }
    None
}

// ─── Metadata entries (default CF) ───────────────────────────────────────────
//
// The default column family stores heterogeneous metadata under well-known byte
// keys. A single TypedCf can't express "key X → type A, key Y → type B", so we
// use per-key phantom types instead.

/// Trait for typed default-CF metadata entries.
///
/// Each entry is a zero-sized struct that declares the key bytes, value type,
/// and codec. This gives the same compile-time key↔type binding as `TypedCf`
/// but for the heterogeneous default CF.
pub(crate) trait MetadataEntry {
    /// The well-known byte key in the default CF.
    const KEY: &'static [u8];
    /// The value type stored under this key.
    type Value;
    /// Codec for encoding/decoding the value.
    type Codec: DbCodec<Self::Value> + Default;
}

/// Read a metadata entry from any readable store.
pub(crate) fn meta_read<E: MetadataEntry>(store: &impl ReadableStore) -> Option<E::Value> {
    store
        .raw_get(E::KEY)
        .map(|bytes| E::Codec::default().decode(&bytes))
}

/// Write a metadata entry into a WriteBatch.
pub(crate) fn meta_write<E: MetadataEntry>(batch: &mut WriteBatch, value: &E::Value) {
    let encoded = E::Codec::default().encode(value);
    batch.put(E::KEY, encoded);
}

// ─── Metadata codecs ─────────────────────────────────────────────────────────

/// BlockHeight codec — wraps BE u64, maps through `BlockHeight(u64)`.
#[derive(Default)]
pub(crate) struct BlockHeightCodec;

impl DbCodec<BlockHeight> for BlockHeightCodec {
    fn encode_to(&self, value: &BlockHeight, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&value.0.to_be_bytes());
    }

    fn decode(&self, bytes: &[u8]) -> BlockHeight {
        let arr: [u8; 8] = bytes.try_into().unwrap_or([0; 8]);
        BlockHeight(u64::from_be_bytes(arr))
    }
}

/// JMT metadata codec — packed 40-byte format: `[version_BE_8B][root_hash_32B]`.
#[derive(Default)]
pub(crate) struct JmtMetadataCodec;

impl DbCodec<(u64, hyperscale_types::StateRoot)> for JmtMetadataCodec {
    fn encode_to(&self, value: &(u64, hyperscale_types::StateRoot), buf: &mut Vec<u8>) {
        buf.extend_from_slice(&value.0.to_be_bytes());
        buf.extend_from_slice(&value.1.as_raw().to_bytes());
    }

    fn decode(&self, bytes: &[u8]) -> (u64, hyperscale_types::StateRoot) {
        assert!(bytes.len() == 40, "jmt:metadata must be 40 bytes");
        let version = u64::from_be_bytes(bytes[..8].try_into().unwrap());
        let root_hash = hyperscale_types::StateRoot::from_raw(
            hyperscale_types::Hash::from_hash_bytes(&bytes[8..40]),
        );
        (version, root_hash)
    }
}

// ─── Metadata entry definitions ──────────────────────────────────────────────

pub(crate) struct CommittedHeightEntry;
impl MetadataEntry for CommittedHeightEntry {
    const KEY: &'static [u8] = b"chain:committed_height";
    type Value = BlockHeight;
    type Codec = BlockHeightCodec;
}

pub(crate) struct CommittedHashEntry;
impl MetadataEntry for CommittedHashEntry {
    const KEY: &'static [u8] = b"chain:committed_hash";
    type Value = hyperscale_types::Hash;
    type Codec = HashCodec;
}

pub(crate) struct CommittedQcEntry;
impl MetadataEntry for CommittedQcEntry {
    const KEY: &'static [u8] = b"chain:committed_qc";
    type Value = hyperscale_types::QuorumCertificate;
    type Codec = SborCodec<hyperscale_types::QuorumCertificate>;
}

pub(crate) struct JmtMetadataEntry;
impl MetadataEntry for JmtMetadataEntry {
    const KEY: &'static [u8] = b"jmt:metadata";
    type Value = (u64, hyperscale_types::StateRoot);
    type Codec = JmtMetadataCodec;
}
