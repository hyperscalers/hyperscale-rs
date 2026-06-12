//! Typed column family API — compile-time key/value type safety for `RocksDB` operations.
//!
//! Each column family is a zero-sized struct implementing [`TypedCf`], which declares
//! the key type, value type, and their encodings. Codecs come in two layers:
//! [`DbEncode`] (write paths) and [`DbCodec`] (adds decode, required for read and
//! iteration paths). A CF whose key codec is encode-only therefore cannot be
//! iterated — misuse is a compile-time error rather than a runtime panic.

use std::marker::PhantomData;

use hyperscale_types::{
    BlockHeight, ChainOrigin, Hash, QuorumCertificate, StateRoot, WeightedTimestamp,
};
use rocksdb::{ColumnFamily, DB, DBRawIteratorWithThreadMode, Snapshot, WriteBatch};
use sbor::prelude::{BasicDecode, BasicEncode};
use sbor::{basic_decode, basic_encode};

use crate::shard::jmt_stored::{StoredNodeKey, encode_key};

// ─── Codec traits ─────────────────────────────────────────────────────────────

/// Encode-only codec: serializes typed values into `RocksDB` byte representations.
///
/// Codecs that can also deserialize (the common case) additionally implement
/// [`DbCodec`]. Write-only codecs (e.g. [`JmtKeyCodec`], whose key format has
/// no inverse in this codebase) implement only `DbEncode`. Iterator helpers
/// require `DbCodec` on the key codec, so attempting to iterate a CF with a
/// write-only key codec is a compile-time error.
pub trait DbEncode<T> {
    fn encode_to(&self, value: &T, buf: &mut Vec<u8>);

    /// Convenience wrapper that allocates a new Vec.
    fn encode(&self, value: &T) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode_to(value, &mut buf);
        buf
    }
}

/// Full codec: encode + decode. Read paths and iterator helpers require this.
pub trait DbCodec<T>: DbEncode<T> {
    fn decode(&self, bytes: &[u8]) -> T;
}

// ─── Codec implementations ───────────────────────────────────────────────────

/// SBOR encode/decode. Covers most types in the codebase.
pub struct SborCodec<T>(PhantomData<T>);

impl<T> Default for SborCodec<T> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<T: BasicEncode> DbEncode<T> for SborCodec<T> {
    fn encode_to(&self, value: &T, buf: &mut Vec<u8>) {
        let encoded = basic_encode(value).expect("SBOR encoding must succeed");
        buf.extend_from_slice(&encoded);
    }
}

impl<T: BasicEncode + BasicDecode> DbCodec<T> for SborCodec<T> {
    fn decode(&self, bytes: &[u8]) -> T {
        basic_decode(bytes).expect("SBOR decoding must succeed")
    }
}

/// Big-endian u64 codec for heights, versions, etc.
/// Preserves lexicographic ordering in `RocksDB`.
#[derive(Default)]
pub struct BeU64Codec;

impl DbEncode<u64> for BeU64Codec {
    fn encode_to(&self, value: &u64, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&value.to_be_bytes());
    }
}

impl DbCodec<u64> for BeU64Codec {
    fn decode(&self, bytes: &[u8]) -> u64 {
        u64::from_be_bytes(bytes.try_into().expect("u64 key must be 8 bytes"))
    }
}

/// 32-byte hash codec.
#[derive(Default)]
pub struct HashCodec;

impl DbEncode<Hash> for HashCodec {
    fn encode_to(&self, value: &Hash, buf: &mut Vec<u8>) {
        buf.extend_from_slice(value.as_bytes());
    }
}

impl DbCodec<Hash> for HashCodec {
    fn decode(&self, bytes: &[u8]) -> Hash {
        Hash::from_hash_bytes(bytes)
    }
}

/// Raw passthrough — value is already `Vec<u8>`.
#[derive(Default)]
pub struct RawCodec;

impl DbEncode<Vec<u8>> for RawCodec {
    fn encode_to(&self, value: &Vec<u8>, buf: &mut Vec<u8>) {
        buf.extend_from_slice(value);
    }
}

impl DbCodec<Vec<u8>> for RawCodec {
    fn decode(&self, bytes: &[u8]) -> Vec<u8> {
        bytes.to_vec()
    }
}

/// JMT node key codec — wraps the existing `encode_key` function.
///
/// Write-only: JMT keys are encoded for writes and point lookups but the
/// format has no decoder in this codebase. Implementing only [`DbEncode`]
/// (and not [`DbCodec`]) ensures any attempt to iterate the JMT-nodes CF
/// or otherwise decode a key is a compile-time error rather than a runtime
/// panic.
#[derive(Default)]
pub struct JmtKeyCodec;

impl DbEncode<StoredNodeKey> for JmtKeyCodec {
    fn encode_to(&self, value: &StoredNodeKey, buf: &mut Vec<u8>) {
        let encoded = encode_key(value);
        buf.extend_from_slice(&encoded);
    }
}

// ─── TypedCf trait ────────────────────────────────────────────────────────────

/// Trait for typed column family definitions.
///
/// Each CF is a zero-sized struct that declares the key/value types and their
/// codecs. This is the single source of truth for "what lives in this CF and
/// how it's encoded."
pub trait TypedCf {
    /// CF name — must match the string used in `RocksDbConfig`.
    /// Not read at runtime by typed helpers (they use [`handle`](Self::handle)),
    /// but serves as documentation and is used by `ALL_COLUMN_FAMILIES`.
    #[allow(dead_code)]
    const NAME: &'static str;

    /// Key type stored in this CF.
    type Key;
    /// Value type stored in this CF.
    type Value;

    /// Codec for encoding keys. Iteration also requires the codec to
    /// implement [`DbCodec`] (i.e. support decoding); CFs whose key codec
    /// is encode-only (e.g. JMT nodes) cannot be iterated, by design.
    type KeyCodec: DbEncode<Self::Key> + Default + 'static;
    /// Codec for encoding/decoding values.
    type ValueCodec: DbCodec<Self::Value> + Default + 'static;

    /// Domain-specific handles struct this CF belongs to. Each backend
    /// (shard, beacon) defines its own; CFs declare which they live in.
    type Handles<'a>;

    /// Extract this CF's handle from the resolved handles struct.
    ///
    /// Each implementation is a single field access — the compiler verifies
    /// the mapping at build time, so there's no runtime string dispatch.
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily;
}

// ─── ReadableStore trait ─────────────────────────────────────────────────────

/// Abstraction over `RocksDB` `DB` and `Snapshot` for typed reads.
///
/// Both `DB` and `Snapshot` support the same `get_cf` / `multi_get_cf` operations
/// but don't share a trait in the `rocksdb` crate. This trait bridges that gap
/// so typed read functions work with either backend.
pub trait ReadableStore {
    fn raw_get_cf(&self, cf: &ColumnFamily, key: &[u8]) -> Option<Vec<u8>>;
    fn raw_multi_get_cf(&self, keys: Vec<(&ColumnFamily, Vec<u8>)>) -> Vec<Option<Vec<u8>>>;
    /// Read from the default column family (no CF handle needed).
    fn raw_get(&self, key: &[u8]) -> Option<Vec<u8>>;
}

impl ReadableStore for DB {
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

impl ReadableStore for Snapshot<'_> {
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
// The RocksDbShardStorage methods become thin wrappers over these.

/// Typed get from any readable store.
pub fn get<CF: TypedCf>(
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
pub fn multi_get<CF: TypedCf>(
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

/// Typed put into a `WriteBatch`.
pub fn batch_put<CF: TypedCf>(
    batch: &mut WriteBatch,
    cf: &ColumnFamily,
    key: &CF::Key,
    value: &CF::Value,
) {
    let key_bytes = CF::KeyCodec::default().encode(key);
    let value_bytes = CF::ValueCodec::default().encode(value);
    batch.put_cf(cf, &key_bytes, &value_bytes);
}

/// Typed put into a `WriteBatch`, using pre-serialized value bytes if available.
pub fn batch_put_raw<CF: TypedCf>(
    batch: &mut WriteBatch,
    cf: &ColumnFamily,
    key: &CF::Key,
    value: &CF::Value,
    raw_value: Option<&[u8]>,
) {
    let key_bytes = CF::KeyCodec::default().encode(key);
    if let Some(bytes) = raw_value {
        batch.put_cf(cf, &key_bytes, bytes);
    } else {
        let value_bytes = CF::ValueCodec::default().encode(value);
        batch.put_cf(cf, &key_bytes, &value_bytes);
    }
}

/// Typed delete in a `WriteBatch`.
pub fn batch_delete<CF: TypedCf>(batch: &mut WriteBatch, cf: &ColumnFamily, key: &CF::Key) {
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
pub fn iter_all<'a, CF: TypedCf>(
    db: &'a DB,
    cf: &ColumnFamily,
) -> impl Iterator<Item = (CF::Key, CF::Value)> + 'a
where
    CF::KeyCodec: DbCodec<CF::Key>,
{
    let mut iter = db.raw_iterator_cf(cf);
    iter.seek_to_first();
    raw_iter_to_typed::<CF>(iter)
}

/// Typed forward iterator over a column family starting at `key`
/// (inclusive). Yields decoded entries to the end of the CF; callers
/// bound the scan with `take_while`.
pub fn iter_from<'a, CF: TypedCf>(
    db: &'a DB,
    cf: &ColumnFamily,
    key: &CF::Key,
) -> impl Iterator<Item = (CF::Key, CF::Value)> + 'a
where
    CF::KeyCodec: DbCodec<CF::Key>,
{
    let key_bytes = CF::KeyCodec::default().encode(key);
    let mut iter = db.raw_iterator_cf(cf);
    iter.seek(&key_bytes);
    raw_iter_to_typed::<CF>(iter)
}

/// Typed prefix-scan iterator over a column family.
///
/// Seeks to `prefix` and yields decoded entries until the key leaves the
/// prefix range. The end bound is computed by incrementing the last byte
/// of the prefix (standard `RocksDB` prefix scan pattern).
pub fn prefix_iter<'a, CF: TypedCf>(
    db: &'a DB,
    cf: &ColumnFamily,
    prefix: &[u8],
) -> impl Iterator<Item = (CF::Key, CF::Value)> + 'a
where
    CF::KeyCodec: DbCodec<CF::Key>,
{
    prefix_iter_from::<CF>(db, cf, prefix, prefix)
}

/// Typed prefix-scan iterator starting from a custom seek position.
///
/// Like [`prefix_iter`], but seeks to `start` instead of the prefix.
/// `start` must be >= `prefix`. The end bound is still `next_prefix(prefix)`.
pub fn prefix_iter_from<'a, CF: TypedCf>(
    db: &'a DB,
    cf: &ColumnFamily,
    prefix: &[u8],
    start: &[u8],
) -> impl Iterator<Item = (CF::Key, CF::Value)> + 'a
where
    CF::KeyCodec: DbCodec<CF::Key>,
{
    let mut iter = db.raw_iterator_cf(cf);
    iter.seek(start);
    let end = next_prefix(prefix);
    bounded_iter_to_typed::<CF>(iter, end)
}

/// Typed prefix-scan iterator over a `RocksDB` snapshot.
///
/// Same as [`prefix_iter`] but reads from a point-in-time snapshot.
pub fn prefix_iter_snap<'a, CF: TypedCf>(
    snapshot: &'a Snapshot<'_>,
    cf: &ColumnFamily,
    prefix: &[u8],
) -> impl Iterator<Item = (CF::Key, CF::Value)> + 'a
where
    CF::KeyCodec: DbCodec<CF::Key>,
{
    prefix_iter_from_snap::<CF>(snapshot, cf, prefix, prefix)
}

/// Typed prefix-scan iterator over a `RocksDB` snapshot with custom seek position.
pub fn prefix_iter_from_snap<'a, CF: TypedCf>(
    snapshot: &'a Snapshot<'_>,
    cf: &ColumnFamily,
    prefix: &[u8],
    start: &[u8],
) -> impl Iterator<Item = (CF::Key, CF::Value)> + 'a
where
    CF::KeyCodec: DbCodec<CF::Key>,
{
    let mut iter = snapshot.raw_iterator_cf(cf);
    iter.seek(start);
    let end = next_prefix(prefix);
    bounded_iter_to_typed::<CF>(iter, end)
}

/// Convert a raw iterator (already seeked) into a typed iterator that yields
/// all remaining entries.
fn raw_iter_to_typed<CF: TypedCf>(
    mut iter: DBRawIteratorWithThreadMode<'_, DB>,
) -> impl Iterator<Item = (CF::Key, CF::Value)> + '_
where
    CF::KeyCodec: DbCodec<CF::Key>,
{
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
fn bounded_iter_to_typed<CF: TypedCf>(
    mut iter: DBRawIteratorWithThreadMode<'_, DB>,
    end: Option<Vec<u8>>,
) -> impl Iterator<Item = (CF::Key, CF::Value)> + '_
where
    CF::KeyCodec: DbCodec<CF::Key>,
{
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
            if let Some(ref end) = end
                && raw_key >= end.as_slice()
            {
                done = true;
                return None;
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
pub trait MetadataEntry {
    /// The well-known byte key in the default CF.
    const KEY: &'static [u8];
    /// The value type stored under this key.
    type Value;
    /// Codec for encoding/decoding the value.
    type Codec: DbCodec<Self::Value> + Default;
}

/// Read a metadata entry from any readable store.
pub fn meta_read<E: MetadataEntry>(store: &impl ReadableStore) -> Option<E::Value> {
    store
        .raw_get(E::KEY)
        .map(|bytes| E::Codec::default().decode(&bytes))
}

/// Write a metadata entry into a `WriteBatch`.
pub fn meta_write<E: MetadataEntry>(batch: &mut WriteBatch, value: &E::Value) {
    let encoded = E::Codec::default().encode(value);
    batch.put(E::KEY, encoded);
}

// ─── Metadata codecs ─────────────────────────────────────────────────────────

/// `BlockHeight` codec — wraps BE u64, maps through `BlockHeight::new(u64)`.
#[derive(Default)]
pub struct BlockHeightCodec;

impl DbEncode<BlockHeight> for BlockHeightCodec {
    fn encode_to(&self, value: &BlockHeight, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&value.inner().to_be_bytes());
    }
}

impl DbCodec<BlockHeight> for BlockHeightCodec {
    fn decode(&self, bytes: &[u8]) -> BlockHeight {
        let arr: [u8; 8] = bytes.try_into().unwrap_or([0; 8]);
        BlockHeight::new(u64::from_be_bytes(arr))
    }
}

/// JMT metadata codec — packed 40-byte format: `[version_BE_8B][root_hash_32B]`.
#[derive(Default)]
pub struct JmtMetadataCodec;

impl DbEncode<(u64, StateRoot)> for JmtMetadataCodec {
    fn encode_to(&self, value: &(u64, StateRoot), buf: &mut Vec<u8>) {
        buf.extend_from_slice(&value.0.to_be_bytes());
        buf.extend_from_slice(&value.1.as_raw().to_bytes());
    }
}

impl DbCodec<(u64, StateRoot)> for JmtMetadataCodec {
    fn decode(&self, bytes: &[u8]) -> (u64, StateRoot) {
        assert!(bytes.len() == 40, "jmt:metadata must be 40 bytes");
        let version = u64::from_be_bytes(bytes[..8].try_into().unwrap());
        let root_hash = StateRoot::from_raw(Hash::from_hash_bytes(&bytes[8..40]));
        (version, root_hash)
    }
}

// ─── Metadata entry definitions ──────────────────────────────────────────────

pub struct CommittedHeightEntry;
impl MetadataEntry for CommittedHeightEntry {
    const KEY: &'static [u8] = b"chain:committed_height";
    type Value = BlockHeight;
    type Codec = BlockHeightCodec;
}

pub struct CommittedHashEntry;
impl MetadataEntry for CommittedHashEntry {
    const KEY: &'static [u8] = b"chain:committed_hash";
    type Value = Hash;
    type Codec = HashCodec;
}

pub struct CommittedQcEntry;
impl MetadataEntry for CommittedQcEntry {
    const KEY: &'static [u8] = b"chain:committed_qc";
    type Value = QuorumCertificate;
    type Codec = SborCodec<QuorumCertificate>;
}

pub struct JmtMetadataEntry;
impl MetadataEntry for JmtMetadataEntry {
    const KEY: &'static [u8] = b"jmt:metadata";
    type Value = (u64, StateRoot);
    type Codec = JmtMetadataCodec;
}

pub struct ChainOriginEntry;
impl MetadataEntry for ChainOriginEntry {
    const KEY: &'static [u8] = b"chain:origin";
    type Value = ChainOrigin;
    type Codec = ChainOriginCodec;
}

/// Chain-origin codec — packed 16-byte format:
/// `[genesis_height_BE_8B][anchor_wt_millis_BE_8B]`.
#[derive(Default)]
pub struct ChainOriginCodec;

impl DbEncode<ChainOrigin> for ChainOriginCodec {
    fn encode_to(&self, value: &ChainOrigin, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&value.genesis_height.inner().to_be_bytes());
        buf.extend_from_slice(&value.anchor_wt.as_millis().to_be_bytes());
    }
}

impl DbCodec<ChainOrigin> for ChainOriginCodec {
    fn decode(&self, bytes: &[u8]) -> ChainOrigin {
        assert!(bytes.len() == 16, "chain:origin must be 16 bytes");
        ChainOrigin {
            genesis_height: BlockHeight::new(u64::from_be_bytes(bytes[..8].try_into().unwrap())),
            anchor_wt: WeightedTimestamp::from_millis(u64::from_be_bytes(
                bytes[8..16].try_into().unwrap(),
            )),
        }
    }
}
