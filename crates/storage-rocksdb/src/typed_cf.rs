//! Typed column family API — compile-time key/value type safety for `RocksDB` operations.
//!
//! Each column family is a zero-sized struct implementing [`TypedCf`], which declares
//! the key type, value type, and their encodings. Codecs come in two layers:
//! [`DbEncode`] (write paths) and [`DbCodec`] (adds decode, required for read and
//! iteration paths). A CF whose key codec is encode-only therefore cannot be
//! iterated — misuse is a compile-time error rather than a runtime panic.

use std::marker::PhantomData;

use hyperscale_hbor::{
    HborDecode, HborEncode, from_slice as hbor_from_slice, to_vec as hbor_to_vec,
};
use hyperscale_jmt::{
    Child, ChildKind, Hash as JmtHash, InternalNode, KEY_BYTES as JMT_KEY_BYTES, LeafNode, Node,
    NodeKey,
};
use hyperscale_storage::{ImportCursor, ImportProgress};
use hyperscale_types::{
    BlockHeight, CertifiedBlockHeader, ChainOrigin, Hash, LEAF_KEY_BYTES, QuorumCertificate,
    StateRoot, WeightedTimestamp,
};
use rocksdb::{ColumnFamily, DB, DBRawIteratorWithThreadMode, Snapshot, WriteBatch};

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

/// HBOR encode/decode. Covers most types in the codebase.
pub struct HborCodec<T>(PhantomData<T>);

impl<T> Default for HborCodec<T> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<T: HborEncode> DbEncode<T> for HborCodec<T> {
    fn encode_to(&self, value: &T, buf: &mut Vec<u8>) {
        let encoded = hbor_to_vec(value).expect("encoding must succeed");
        buf.extend_from_slice(&encoded);
    }
}

impl<T: HborEncode + HborDecode> DbCodec<T> for HborCodec<T> {
    fn decode(&self, bytes: &[u8]) -> T {
        hbor_from_slice(bytes).expect("decoding must succeed")
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

/// JMT node key codec — the tree's own canonical encoding,
/// `version_be (8B) || bits_be (2B) || path_bytes`. Version-first
/// ordering groups a version's writes together, which is what makes
/// pruning a range delete.
///
/// Write-only: nothing in this backend reads a node key back, and
/// implementing only [`DbEncode`] (not [`DbCodec`]) makes any attempt to
/// iterate the JMT-nodes CF a compile-time error rather than a runtime
/// panic.
#[derive(Default)]
pub struct JmtKeyCodec;

impl DbEncode<NodeKey> for JmtKeyCodec {
    fn encode_to(&self, value: &NodeKey, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&value.encode());
    }
}

/// Backend tree arity. Binary, and a child bitmask byte bounds it at 8 —
/// changing either is a data migration.
const JMT_ARITY: usize = 2;

/// Stored layout version. Bump when the packing below changes.
const JMT_NODE_FORMAT: u8 = 1;
const JMT_NODE_INTERNAL: u8 = 0;
const JMT_NODE_LEAF: u8 = 1;
const JMT_CHILD_INTERNAL: u8 = 0;
const JMT_CHILD_LEAF: u8 = 1;

/// Take `n` bytes, or panic: a short record is storage corruption.
fn jmt_split<'a>(bytes: &'a [u8], at: &mut usize, n: usize) -> &'a [u8] {
    let end = *at + n;
    assert!(end <= bytes.len(), "jmt node record truncated");
    let out = &bytes[*at..end];
    *at = end;
    out
}

fn jmt_hash(bytes: &[u8]) -> JmtHash {
    bytes.try_into().expect("jmt hash field is 32 bytes")
}

/// JMT node codec.
///
/// Packs [`Node`] directly. Every field is fixed width: hashes are 32
/// bytes rather than length-prefixed vectors, the child set is a presence
/// bitmask, and `ChildKind` keeps its two cases instead of collapsing to
/// a bool. That width matters beyond size — an internal node's stored
/// hash is returned as-is by `Node::hash` rather than recomputed from its
/// children, so a decode that silently accepted a wrong-length hash would
/// yield a wrong state root with no structural error to catch it.
#[derive(Default)]
pub struct JmtNodeCodec;

impl DbEncode<Node> for JmtNodeCodec {
    fn encode_to(&self, value: &Node, buf: &mut Vec<u8>) {
        buf.push(JMT_NODE_FORMAT);
        match value {
            Node::Internal(internal) => {
                buf.push(JMT_NODE_INTERNAL);
                buf.extend_from_slice(&internal.hash);
                let mut mask = 0u8;
                for (bucket, child) in internal.children.iter().enumerate() {
                    if child.is_some() {
                        assert!(
                            bucket < JMT_ARITY,
                            "child bucket {bucket} exceeds backend arity"
                        );
                        mask |= 1u8 << bucket;
                    }
                }
                buf.push(mask);
                for child in internal.children.iter().flatten() {
                    buf.extend_from_slice(&child.version.to_be_bytes());
                    buf.extend_from_slice(&child.hash);
                    buf.push(match child.kind {
                        ChildKind::Internal => JMT_CHILD_INTERNAL,
                        ChildKind::Leaf => JMT_CHILD_LEAF,
                    });
                }
            }
            Node::Leaf(leaf) => {
                buf.push(JMT_NODE_LEAF);
                buf.extend_from_slice(&leaf.key);
                buf.extend_from_slice(&leaf.value_hash);
                buf.extend_from_slice(&leaf.value_len.to_be_bytes());
            }
        }
    }
}

impl DbCodec<Node> for JmtNodeCodec {
    fn decode(&self, bytes: &[u8]) -> Node {
        let mut at = 0usize;
        let header = jmt_split(bytes, &mut at, 2);
        assert_eq!(
            header[0], JMT_NODE_FORMAT,
            "unknown stored jmt node format {}",
            header[0]
        );
        match header[1] {
            JMT_NODE_INTERNAL => {
                let hash = jmt_hash(jmt_split(bytes, &mut at, 32));
                let mask = jmt_split(bytes, &mut at, 1)[0];
                assert!(
                    usize::from(mask) >> JMT_ARITY == 0,
                    "stored child mask {mask:#b} names a bucket beyond the backend arity"
                );
                let mut children: Vec<Option<Child>> = vec![None; JMT_ARITY];
                for (bucket, slot) in children.iter_mut().enumerate() {
                    if mask & (1u8 << bucket) == 0 {
                        continue;
                    }
                    let version = u64::from_be_bytes(
                        jmt_split(bytes, &mut at, 8)
                            .try_into()
                            .expect("jmt child version is 8 bytes"),
                    );
                    let child_hash = jmt_hash(jmt_split(bytes, &mut at, 32));
                    let kind = match jmt_split(bytes, &mut at, 1)[0] {
                        JMT_CHILD_INTERNAL => ChildKind::Internal,
                        JMT_CHILD_LEAF => ChildKind::Leaf,
                        other => panic!("unknown stored jmt child kind {other}"),
                    };
                    *slot = Some(Child {
                        version,
                        hash: child_hash,
                        kind,
                    });
                }
                Node::Internal(InternalNode { children, hash })
            }
            JMT_NODE_LEAF => {
                let key = jmt_split(bytes, &mut at, JMT_KEY_BYTES)
                    .try_into()
                    .expect("jmt leaf key is KEY_BYTES");
                let value_hash = jmt_hash(jmt_split(bytes, &mut at, 32));
                let value_len = u64::from_be_bytes(
                    jmt_split(bytes, &mut at, 8)
                        .try_into()
                        .expect("jmt value length is 8 bytes"),
                );
                Node::Leaf(LeafNode {
                    key,
                    value_hash,
                    value_len,
                })
            }
            other => panic!("unknown stored jmt node tag {other}"),
        }
    }
}

/// Stale JMT node keys, as a run of canonical [`NodeKey`] encodings.
///
/// Each encoding carries its own path bit count, so the run needs no
/// separators — the bit count fixes how many path bytes follow.
#[derive(Default)]
pub struct JmtStaleKeysCodec;

impl DbEncode<Vec<NodeKey>> for JmtStaleKeysCodec {
    fn encode_to(&self, value: &Vec<NodeKey>, buf: &mut Vec<u8>) {
        for key in value {
            buf.extend_from_slice(&key.encode());
        }
    }
}

impl DbCodec<Vec<NodeKey>> for JmtStaleKeysCodec {
    fn decode(&self, bytes: &[u8]) -> Vec<NodeKey> {
        let mut out = Vec::new();
        let mut at = 0usize;
        while at < bytes.len() {
            assert!(at + 10 <= bytes.len(), "stale jmt key run truncated");
            let bits = u16::from_be_bytes([bytes[at + 8], bytes[at + 9]]);
            let len = 10 + usize::from(bits).div_ceil(8);
            let key = NodeKey::decode(jmt_split(bytes, &mut at, len))
                .expect("a stored stale key decodes");
            out.push(key);
        }
        out
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

/// Delete a metadata entry in `batch`. Reads of an absent entry return
/// `None` (or the accessor's documented default).
pub fn meta_delete<E: MetadataEntry>(batch: &mut WriteBatch) {
    batch.delete(E::KEY);
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
    type Codec = HborCodec<QuorumCertificate>;
}

pub struct JmtMetadataEntry;
impl MetadataEntry for JmtMetadataEntry {
    const KEY: &'static [u8] = b"jmt:metadata";
    type Value = (u64, StateRoot);
    type Codec = JmtMetadataCodec;
}

/// The oldest version still inside the retention horizon.
///
/// Stored rather than derived, because four readers ask for it — a
/// historical cell read, a historical range read, `snapshot_at`, and both
/// garbage collectors — and what a reader may ask for has to be exactly
/// what the collector has not deleted.
pub struct RetentionFloorEntry;
impl MetadataEntry for RetentionFloorEntry {
    const KEY: &'static [u8] = b"jmt:retention_floor";
    type Value = u64;
    type Codec = HborCodec<u64>;
}

pub struct ChainOriginEntry;
impl MetadataEntry for ChainOriginEntry {
    const KEY: &'static [u8] = b"chain:origin";
    type Value = ChainOrigin;
    type Codec = ChainOriginCodec;
}

/// The certified header of the boundary a snap-sync imported, held
/// without its block so the store serves the next joiner's witness
/// history as one that committed the block would.
pub struct BoundaryHeaderEntry;
impl MetadataEntry for BoundaryHeaderEntry {
    const KEY: &'static [u8] = b"import:boundary_header";
    type Value = CertifiedBlockHeader;
    type Codec = HborCodec<CertifiedBlockHeader>;
}

/// The staged snap-sync import's progress record, written atomically
/// with every staged chunk and deleted by wipe / finalize.
pub struct ImportProgressEntry;
impl MetadataEntry for ImportProgressEntry {
    const KEY: &'static [u8] = b"import:progress";
    type Value = ImportProgress;
    type Codec = ImportProgressCodec;
}

/// Import-progress codec — packed
/// `[anchor_height_BE_8B][anchor_root_32B][split_bits_1B][chunk_limit_BE_4B]`
/// `[staged_bytes_BE_8B]` then per cursor `[next_32B][end_32B][done_1B]`.
#[derive(Default)]
pub struct ImportProgressCodec;

/// Fixed prefix ahead of the cursor list.
const IMPORT_PROGRESS_HEADER: usize = 8 + 32 + 1 + 4 + 8;
/// Packed size of one cursor record.
const IMPORT_CURSOR_BYTES: usize = LEAF_KEY_BYTES + LEAF_KEY_BYTES + 1;

impl DbEncode<ImportProgress> for ImportProgressCodec {
    fn encode_to(&self, value: &ImportProgress, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&value.anchor_height.inner().to_be_bytes());
        buf.extend_from_slice(&value.anchor_state_root.as_raw().to_bytes());
        buf.push(value.split_bits);
        buf.extend_from_slice(&value.chunk_limit.to_be_bytes());
        buf.extend_from_slice(&value.staged_bytes.to_be_bytes());
        for cursor in &value.cursors {
            buf.extend_from_slice(&cursor.next);
            buf.extend_from_slice(&cursor.end);
            buf.push(u8::from(cursor.done));
        }
    }
}

impl DbCodec<ImportProgress> for ImportProgressCodec {
    fn decode(&self, bytes: &[u8]) -> ImportProgress {
        assert!(
            bytes.len() >= IMPORT_PROGRESS_HEADER
                && (bytes.len() - IMPORT_PROGRESS_HEADER).is_multiple_of(IMPORT_CURSOR_BYTES),
            "import progress record has a malformed length",
        );
        let anchor_height = BlockHeight::new(u64::from_be_bytes(
            bytes[..8].try_into().expect("length checked above"),
        ));
        let anchor_state_root = StateRoot::from_raw(Hash::from_hash_bytes(&bytes[8..40]));
        let split_bits = bytes[40];
        let chunk_limit =
            u32::from_be_bytes(bytes[41..45].try_into().expect("length checked above"));
        let staged_bytes =
            u64::from_be_bytes(bytes[45..53].try_into().expect("length checked above"));
        let cursors = bytes[IMPORT_PROGRESS_HEADER..]
            .as_chunks::<IMPORT_CURSOR_BYTES>()
            .0
            .iter()
            .map(|chunk| ImportCursor {
                next: chunk[..LEAF_KEY_BYTES]
                    .try_into()
                    .expect("chunk is one cursor wide"),
                end: chunk[LEAF_KEY_BYTES..2 * LEAF_KEY_BYTES]
                    .try_into()
                    .expect("chunk is one cursor wide"),
                done: chunk[2 * LEAF_KEY_BYTES] != 0,
            })
            .collect();
        ImportProgress {
            anchor_height,
            anchor_state_root,
            split_bits,
            chunk_limit,
            staged_bytes,
            cursors,
        }
    }
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

#[cfg(test)]
mod tests {
    use hyperscale_jmt::{
        Blake3Hasher, InternalNode as JmtInternal, KEY_BYTES, LeafNode as JmtLeaf,
    };

    use super::*;

    #[test]
    fn a_leaf_survives_the_packed_round_trip() {
        let leaf = Node::Leaf(JmtLeaf::new([1u8; KEY_BYTES], [2u8; 32], 17));
        let bytes = JmtNodeCodec.encode(&leaf);
        assert_eq!(JmtNodeCodec.decode(&bytes), leaf);
    }

    /// Both child slots occupied, with the two `ChildKind` cases and
    /// distinct versions — the fields the old mirror flattened to a bool
    /// and a length-prefixed vector.
    #[test]
    fn an_internal_node_survives_the_packed_round_trip() {
        let children = vec![
            Some(Child {
                version: 1,
                hash: [0xAA; 32],
                kind: ChildKind::Leaf,
            }),
            Some(Child {
                version: 2,
                hash: [0xBB; 32],
                kind: ChildKind::Internal,
            }),
        ];
        let node = Node::Internal(JmtInternal::new::<Blake3Hasher>(children));
        let bytes = JmtNodeCodec.encode(&node);
        let back = JmtNodeCodec.decode(&bytes);
        assert_eq!(back, node);
        // The stored hash is returned as-is rather than recomputed, so a
        // decode that lost it would produce a wrong state root silently.
        assert_eq!(back.hash::<Blake3Hasher>(), node.hash::<Blake3Hasher>());
    }

    #[test]
    fn a_sparse_internal_node_survives_the_packed_round_trip() {
        let children = vec![
            None,
            Some(Child {
                version: 7,
                hash: [0xCC; 32],
                kind: ChildKind::Leaf,
            }),
        ];
        let node = Node::Internal(JmtInternal::new::<Blake3Hasher>(children));
        let bytes = JmtNodeCodec.encode(&node);
        assert_eq!(JmtNodeCodec.decode(&bytes), node);
    }

    /// Version-first ordering is what lets pruning delete a version's
    /// nodes as one range.
    #[test]
    fn node_keys_sort_by_version_then_path() {
        let a = JmtKeyCodec.encode(&NodeKey::root(1));
        let b = JmtKeyCodec.encode(&NodeKey::root(2));
        assert!(a < b);
    }

    #[test]
    fn a_stale_key_run_round_trips_with_mixed_path_lengths() {
        let keys = vec![
            NodeKey::root(1),
            NodeKey::root(2).child(2, 1, 1),
            NodeKey::root(3).child(3, 0, 1).child(3, 1, 1),
        ];
        let bytes = JmtStaleKeysCodec.encode(&keys);
        assert_eq!(JmtStaleKeysCodec.decode(&bytes), keys);
    }
}
