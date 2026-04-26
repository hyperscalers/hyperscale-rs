//! Node types and key-path representation.
//!
//! A JMT node is either:
//! - [`InternalNode`]: holds up to `ARITY` children. Each child references
//!   either a sub-internal-node or a leaf by hash + version.
//! - [`LeafNode`]: terminates a path. Holds the full key and value hash.
//!
//! Empty subtrees are implicit: an internal-node slot with no child is
//! absent from its children vector and hashes as [`EMPTY_HASH`] when
//! computing the parent.
//!
//! # Path compression
//!
//! Following standard JMT design: when insertion would leave a chain of
//! single-child internal nodes, those nodes collapse and the leaf is
//! placed at the divergence point. This keeps tree depth proportional
//! to `log_ARITY(n_active)` rather than the full key bit-width.

use crate::hasher::{Hash, EMPTY_HASH};

/// Fixed 32-byte key. Callers hash variable-length application keys to
/// 32 bytes before calling into the tree.
pub type Key = [u8; 32];

/// Pre-computed hash of a stored value. The tree stores only the hash;
/// the value itself lives in application storage alongside.
pub type ValueHash = Hash;

/// Maximum tree depth in bits. A 32-byte key has 256 bits; for any
/// supported arity (1, 2, or 4 bits per level) the depth is bounded by
/// `256 / ARITY_BITS`.
pub const MAX_DEPTH_BITS: u16 = 256;

// ============================================================
// NibblePath: compact bit-path representation
// ============================================================

/// A bit path from the tree root, packed MSB-first.
///
/// The name "nibble path" is vestigial — for generic arity it's really
/// a bit path, with each level consuming `ARITY_BITS` bits. We keep the
/// term since it's conventional in JMT literature.
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct NibblePath {
    /// Bits packed MSB-first. `bytes.len() == (bits + 7) / 8`.
    bytes: Vec<u8>,
    /// Number of meaningful bits. Bits beyond this in `bytes` must be 0.
    bits: u16,
}

impl std::fmt::Debug for NibblePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NibblePath")
            .field("bits", &self.bits)
            .field("bytes", &format_args!("{}", hex_lite(&self.bytes)))
            .finish()
    }
}

impl NibblePath {
    /// Empty path (zero bits).
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Build a path over exactly the first `bits` MSB bits of `key`.
    #[must_use]
    pub fn from_key_prefix(key: &Key, bits: u16) -> Self {
        debug_assert!(usize::from(bits) <= key.len() * 8);
        let byte_len = usize::from(bits).div_ceil(8);
        let mut bytes = key[..byte_len].to_vec();
        // Mask off unused trailing bits in the final byte.
        let trailing = (8 - (usize::from(bits) % 8)) % 8;
        if trailing > 0 {
            if let Some(last) = bytes.last_mut() {
                *last &= 0xFFu8 << trailing;
            }
        }
        Self { bytes, bits }
    }

    /// Number of meaningful bits.
    #[must_use]
    pub fn len(&self) -> u16 {
        self.bits
    }

    /// Whether this path has zero bits.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bits == 0
    }

    /// Extract the next `count` bits (up to 8) starting at bit offset
    /// `from` (from MSB). Returns them right-aligned in a `u8`.
    ///
    /// # Panics
    ///
    /// Panics (in debug) if `from + count > self.bits` or `count > 8`.
    #[must_use]
    pub fn bits_at(&self, from: u16, count: u8) -> u8 {
        debug_assert!(count <= 8);
        debug_assert!(from + u16::from(count) <= self.bits);

        let from = from as usize;
        let count = count as usize;
        let byte = from / 8;
        let off = from % 8;

        // Bits may straddle two bytes.
        let hi = u16::from(self.bytes[byte]);
        let lo = u16::from(*self.bytes.get(byte + 1).unwrap_or(&0));
        let combined = (hi << 8) | lo;
        let shift = 16 - off - count;
        let mask = (1u16 << count) - 1;
        u8::try_from((combined >> shift) & mask).unwrap_or(u8::MAX)
    }

    /// Append `count` bits (right-aligned in `nibble`, where `count <= 8`).
    pub fn push_bits(&mut self, nibble: u8, count: u8) {
        debug_assert!(count <= 8);
        debug_assert!(self.bits as usize + count as usize <= MAX_DEPTH_BITS as usize);

        let mask = (1u16 << count) - 1;
        let value = u16::from(nibble) & mask;

        // Position in the bit stream where this nibble begins.
        let start = self.bits as usize;
        let end = start + count as usize;
        let needed_bytes = end.div_ceil(8);
        if self.bytes.len() < needed_bytes {
            self.bytes.resize(needed_bytes, 0);
        }

        let byte = start / 8;
        let off = start % 8;
        // Place `value` so its MSB lands at bit offset `off` from the MSB
        // of `self.bytes[byte]`.
        let shift = 16 - off - count as usize;
        let placed = value << shift;
        self.bytes[byte] |= u8::try_from(placed >> 8).unwrap_or(u8::MAX);
        if byte + 1 < self.bytes.len() {
            self.bytes[byte + 1] |= u8::try_from(placed & 0xFF).unwrap_or(u8::MAX);
        }

        self.bits = u16::try_from(end).unwrap_or(u16::MAX);
    }

    /// Canonical byte encoding: `bits_be (2B) || path_bytes`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 + self.bytes.len());
        buf.extend_from_slice(&self.bits.to_be_bytes());
        buf.extend_from_slice(&self.bytes);
        buf
    }

    /// Decode a path from the canonical encoding produced by
    /// [`NibblePath::encode`].
    ///
    /// # Errors
    ///
    /// Returns [`PathDecodeError`] if the buffer is truncated or its byte
    /// length disagrees with the encoded bit count.
    pub fn decode(bytes: &[u8]) -> Result<Self, PathDecodeError> {
        if bytes.len() < 2 {
            return Err(PathDecodeError::Truncated);
        }
        let bits = u16::from_be_bytes([bytes[0], bytes[1]]);
        let path_bytes = &bytes[2..];
        let expected = usize::from(bits).div_ceil(8);
        if path_bytes.len() != expected {
            return Err(PathDecodeError::LengthMismatch {
                bits,
                expected,
                actual: path_bytes.len(),
            });
        }
        Ok(Self {
            bytes: path_bytes.to_vec(),
            bits,
        })
    }

    /// Borrow the packed-bit representation.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Error produced by [`NibblePath::decode`] / [`NodeKey::decode`].
#[derive(Debug, thiserror::Error)]
pub enum PathDecodeError {
    /// Buffer ended before the bit-length prefix could be read.
    #[error("buffer truncated — need at least 2 bytes for bit-length prefix")]
    Truncated,
    /// Path-byte count does not match the encoded bit count.
    #[error("path byte length mismatch: bits={bits} implies {expected} bytes, got {actual}")]
    LengthMismatch {
        /// Encoded bit count.
        bits: u16,
        /// Bytes implied by `bits` (`bits.div_ceil(8)`).
        expected: usize,
        /// Bytes actually present after the prefix.
        actual: usize,
    },
}

fn hex_lite(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut s, "{b:02x}").expect("write to String never fails");
    }
    s
}

// ============================================================
// NodeKey: version + path, uniquely identifies a node in storage
// ============================================================

/// Identifies a node in versioned storage. LSM-friendly: version is big-endian
/// in the encoded form, so writes for version V sort after V-1.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct NodeKey {
    /// Tree version this node was written at.
    pub version: u64,
    /// Bit path from the root locating this node.
    pub path: NibblePath,
}

impl NodeKey {
    /// Build a key from an explicit version and path.
    #[must_use]
    pub fn new(version: u64, path: NibblePath) -> Self {
        Self { version, path }
    }

    /// Key for the root node at the given version.
    #[must_use]
    pub fn root(version: u64) -> Self {
        Self {
            version,
            path: NibblePath::empty(),
        }
    }

    /// Depth of this node measured in bits from the root.
    #[must_use]
    pub fn depth_bits(&self) -> u16 {
        self.path.bits
    }

    /// Create a child key by extending this path with `count` bits.
    #[must_use]
    pub fn child(&self, version: u64, nibble: u8, count: u8) -> Self {
        let mut path = self.path.clone();
        path.push_bits(nibble, count);
        Self { version, path }
    }

    /// Canonical storage encoding: `version_be (8B) || path.encode()`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let path = self.path.encode();
        let mut buf = Vec::with_capacity(8 + path.len());
        buf.extend_from_slice(&self.version.to_be_bytes());
        buf.extend_from_slice(&path);
        buf
    }

    /// Decode from the canonical encoding produced by [`NodeKey::encode`].
    ///
    /// # Errors
    ///
    /// Returns [`PathDecodeError`] if the buffer is truncated or the path
    /// suffix fails to decode.
    pub fn decode(bytes: &[u8]) -> Result<Self, PathDecodeError> {
        if bytes.len() < 8 {
            return Err(PathDecodeError::Truncated);
        }
        let version = u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        let path = NibblePath::decode(&bytes[8..])?;
        Ok(Self { version, path })
    }
}

// ============================================================
// Nodes
// ============================================================

/// A tree node — either internal (with children) or a leaf (terminal).
#[derive(Clone, Debug)]
pub enum Node {
    /// An internal node with one or more child slots.
    Internal(InternalNode),
    /// A terminal leaf carrying a key and its value hash.
    Leaf(LeafNode),
}

impl Node {
    /// Hash of this node. For internal nodes this is pre-computed and
    /// cached; for leaves it's recomputed on demand.
    #[must_use]
    pub fn hash<H: crate::hasher::Hasher>(&self) -> Hash {
        match self {
            Node::Internal(n) => n.hash,
            Node::Leaf(n) => H::hash_leaf(&n.key, &n.value_hash),
        }
    }
}

/// Internal node with up to `ARITY` children.
///
/// Children are stored as a dense `Vec<Option<Child>>` of length `ARITY`.
/// This simplifies hashing (fixed-size input to `hash_internal`) at the
/// cost of carrying `Option` overhead for sparse nodes; for small arity
/// (2-16) that overhead is negligible.
#[derive(Clone, Debug)]
pub struct InternalNode {
    /// Dense child slots; length equals `ARITY`. `None` means empty subtree.
    pub children: Vec<Option<Child>>,
    /// Cached hash over `children` (computed at construction).
    pub hash: Hash,
}

impl InternalNode {
    /// Construct an internal node and pre-compute its hash.
    #[must_use]
    pub fn new<H: crate::hasher::Hasher>(children: Vec<Option<Child>>) -> Self {
        let hash = Self::compute_hash::<H>(&children);
        Self { children, hash }
    }

    /// Hash an internal node's children without constructing one.
    #[must_use]
    pub fn compute_hash<H: crate::hasher::Hasher>(children: &[Option<Child>]) -> Hash {
        let flat: Vec<Hash> = children
            .iter()
            .map(|c| c.as_ref().map_or(EMPTY_HASH, |c| c.hash))
            .collect();
        H::hash_internal(&flat)
    }

    /// Length of the children slot vector (i.e. `ARITY`).
    #[must_use]
    pub fn arity(&self) -> usize {
        self.children.len()
    }

    /// Number of populated child slots.
    #[must_use]
    pub fn child_count(&self) -> usize {
        self.children.iter().filter(|c| c.is_some()).count()
    }
}

/// Reference to a child node held by an internal node's slot.
#[derive(Clone, Debug)]
pub struct Child {
    /// Version at which the referenced node was written.
    pub version: u64,
    /// Hash of the referenced node.
    pub hash: Hash,
    /// Discriminator so consumers don't need to fetch the node just to
    /// know whether the hash refers to a leaf or an internal node.
    pub kind: ChildKind,
}

/// Whether a [`Child`] reference points at an internal node or a leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChildKind {
    /// Reference points to another [`InternalNode`].
    Internal,
    /// Reference points to a [`LeafNode`].
    Leaf,
}

/// A leaf node. Stores the full key (for divergence detection during
/// non-inclusion proofs) and the value hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafNode {
    /// Full 32-byte key located at this leaf.
    pub key: Key,
    /// Pre-computed hash of the stored value.
    pub value_hash: ValueHash,
}

impl LeafNode {
    /// Construct a leaf node from its key and value hash.
    #[must_use]
    pub fn new(key: Key, value_hash: ValueHash) -> Self {
        Self { key, value_hash }
    }
}

// ============================================================
// Update batch: output of apply_updates, input to persistence
// ============================================================

/// Records a node that became stale at a specific version so that
/// pruning can later reclaim its storage.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StaleNodeIndex {
    /// Version at which `node_key` ceased to be live.
    pub stale_since_version: u64,
    /// Key of the node that became stale.
    pub node_key: NodeKey,
}

/// The persistable output of a tree update.
#[derive(Clone, Debug, Default)]
pub struct TreeUpdateBatch {
    /// Nodes to insert into storage.
    pub new_nodes: Vec<(NodeKey, Node)>,
    /// Nodes that the update made unreachable.
    pub stale_nodes: Vec<StaleNodeIndex>,
    /// New `(version, root_key)` mapping, if the tree changed.
    pub root_key: Option<(u64, NodeKey)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_and_read_bits_roundtrip() {
        let mut p = NibblePath::empty();
        p.push_bits(0b1, 1);
        p.push_bits(0b0, 1);
        p.push_bits(0b11, 2);
        p.push_bits(0b0101, 4);
        assert_eq!(p.len(), 8);
        assert_eq!(p.bits_at(0, 1), 0b1);
        assert_eq!(p.bits_at(1, 1), 0b0);
        assert_eq!(p.bits_at(2, 2), 0b11);
        assert_eq!(p.bits_at(4, 4), 0b0101);
    }

    #[test]
    fn from_key_prefix_truncates_and_masks() {
        let key = [0xFFu8; 32];
        let p = NibblePath::from_key_prefix(&key, 12);
        assert_eq!(p.len(), 12);
        // First 8 bits should be all-1s.
        assert_eq!(p.bits_at(0, 8), 0xFF);
        // Next 4 bits should be all-1s.
        assert_eq!(p.bits_at(8, 4), 0x0F);
    }

    #[test]
    fn node_key_encoding_sorts_by_version() {
        let a = NodeKey::root(1).encode();
        let b = NodeKey::root(2).encode();
        assert!(a < b, "version 1 must sort before version 2");
    }
}
