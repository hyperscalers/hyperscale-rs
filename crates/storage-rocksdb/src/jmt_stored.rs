//! SBOR-serializable mirror types for JMT tree persistence.
//!
//! The `hyperscale-jmt` crate keeps its own types ecosystem-neutral (no
//! serde, no SBOR). This module provides `Stored*` mirrors that derive
//! SBOR and convert both ways, plus a RocksDB-key encoding tuned for
//! LSM-friendly sort order (version-first).
//!
//! Tree arity is fixed at binary for this backend. Switching arities
//! later would be a data migration.

use hyperscale_jmt as jmt;
use sbor::prelude::*;

/// Version = block height.
pub type Version = u64;

/// Backend arity exponent. Binary (2^1 = 2 children per internal node).
const BACKEND_ARITY_BITS: u8 = 1;
const BACKEND_ARITY: usize = 1 << BACKEND_ARITY_BITS as usize;

// ============================================================
// StoredNodeKey
// ============================================================

/// SBOR-serializable form of [`jmt::NodeKey`]. Carries the path's bit
/// length explicitly so sub-byte paths (binary trees) roundtrip cleanly.
#[derive(
    Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, BasicCategorize, BasicEncode, BasicDecode,
)]
pub struct StoredNodeKey {
    version: Version,
    /// Number of meaningful bits in `path_bytes`.
    path_bits: u16,
    /// Path bytes packed MSB-first, `ceil(path_bits / 8)` bytes long.
    path_bytes: Vec<u8>,
}

impl StoredNodeKey {
    pub fn from_jmt(key: &jmt::NodeKey) -> Self {
        Self {
            version: key.version,
            path_bits: key.path.len(),
            path_bytes: key.path.as_bytes().to_vec(),
        }
    }

    pub fn to_jmt(&self) -> Result<jmt::NodeKey, jmt::PathDecodeError> {
        let mut encoded = Vec::with_capacity(8 + 2 + self.path_bytes.len());
        encoded.extend_from_slice(&self.version.to_be_bytes());
        encoded.extend_from_slice(&self.path_bits.to_be_bytes());
        encoded.extend_from_slice(&self.path_bytes);
        jmt::NodeKey::decode(&encoded)
    }

    pub fn version(&self) -> Version {
        self.version
    }

    pub fn path_bits(&self) -> u16 {
        self.path_bits
    }

    pub fn path_bytes(&self) -> &[u8] {
        &self.path_bytes
    }
}

/// Encode for RocksDB key storage.
///
/// Format: `version_be (8B) || path_bits_be (2B) || path_bytes`.
/// Version-first ordering groups same-version writes together, which is
/// friendly for LSM compaction and range deletes during pruning.
pub fn encode_key(key: &StoredNodeKey) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + 2 + key.path_bytes.len());
    buf.extend_from_slice(&key.version.to_be_bytes());
    buf.extend_from_slice(&key.path_bits.to_be_bytes());
    buf.extend_from_slice(&key.path_bytes);
    buf
}

// ============================================================
// Stored node value
// ============================================================

/// Versioned wrapper for schema evolution. Bump a new variant when the
/// stored node layout changes incompatibly.
#[derive(Clone, PartialEq, Eq, Hash, Debug, BasicCategorize, BasicEncode, BasicDecode)]
pub enum VersionedStoredNode {
    V1(StoredNode),
}

impl VersionedStoredNode {
    pub fn from_latest(node: StoredNode) -> Self {
        Self::V1(node)
    }

    pub fn into_latest(self) -> StoredNode {
        match self {
            Self::V1(n) => n,
        }
    }
}

/// SBOR-serializable mirror of [`jmt::Node`].
#[derive(Clone, PartialEq, Eq, Hash, Debug, BasicCategorize, BasicEncode, BasicDecode)]
pub enum StoredNode {
    Internal(StoredInternalNode),
    Leaf(StoredLeafNode),
}

/// Internal node: sparse children + cached content hash.
#[derive(Clone, PartialEq, Eq, Hash, Debug, BasicCategorize, BasicEncode, BasicDecode)]
pub struct StoredInternalNode {
    /// Sparse: only non-empty children, sorted by `bucket`.
    pub children: Vec<StoredChildEntry>,
    /// Cached hash (saves recomputation on every read).
    pub hash: Vec<u8>,
}

/// A child reference held in an internal node.
#[derive(Clone, PartialEq, Eq, Hash, Debug, BasicCategorize, BasicEncode, BasicDecode)]
pub struct StoredChildEntry {
    pub bucket: u8,
    pub version: u64,
    pub hash: Vec<u8>,
    /// `true` iff the child is a leaf. Exposed so consumers can avoid
    /// loading the child node just to discover its kind.
    pub is_leaf: bool,
}

/// Leaf node: full key + value hash.
#[derive(Clone, PartialEq, Eq, Hash, Debug, BasicCategorize, BasicEncode, BasicDecode)]
pub struct StoredLeafNode {
    pub key: Vec<u8>,
    pub value_hash: Vec<u8>,
}

/// Identifies a region of the tree eligible for pruning.
///
/// Currently only `Node` is ever emitted by the write path — JMT never
/// produces subtree-wide stale regions at its current arity. Kept as an
/// enum so that future tree variants (e.g. higher-arity subtree stales)
/// can be added without a schema change.
#[derive(Clone, PartialEq, Eq, Hash, Debug, BasicCategorize, BasicEncode, BasicDecode)]
pub enum StaleTreePart {
    /// A single node.
    Node(StoredNodeKey),
}

// ============================================================
// JMT <-> Stored conversions
// ============================================================

impl StoredNode {
    pub fn from_jmt(node: &jmt::Node) -> Self {
        match node {
            jmt::Node::Internal(internal) => {
                let children: Vec<StoredChildEntry> = internal
                    .children
                    .iter()
                    .enumerate()
                    .filter_map(|(bucket, child_opt)| {
                        child_opt.as_ref().map(|c| StoredChildEntry {
                            bucket: bucket as u8,
                            version: c.version,
                            hash: c.hash.to_vec(),
                            is_leaf: matches!(c.kind, jmt::ChildKind::Leaf),
                        })
                    })
                    .collect();
                StoredNode::Internal(StoredInternalNode {
                    children,
                    hash: internal.hash.to_vec(),
                })
            }
            jmt::Node::Leaf(leaf) => StoredNode::Leaf(StoredLeafNode {
                key: leaf.key.to_vec(),
                value_hash: leaf.value_hash.to_vec(),
            }),
        }
    }

    /// Convert back to a `jmt::Node`. Panics if stored hash or key bytes
    /// are the wrong length — that indicates storage corruption and is
    /// not recoverable.
    pub fn to_jmt(&self) -> jmt::Node {
        match self {
            StoredNode::Internal(internal) => {
                let mut dense: Vec<Option<jmt::Child>> = vec![None; BACKEND_ARITY];
                for entry in &internal.children {
                    let kind = if entry.is_leaf {
                        jmt::ChildKind::Leaf
                    } else {
                        jmt::ChildKind::Internal
                    };
                    let bucket = entry.bucket as usize;
                    if bucket >= BACKEND_ARITY {
                        panic!(
                            "stored child bucket {} exceeds backend arity {}",
                            bucket, BACKEND_ARITY
                        );
                    }
                    dense[bucket] = Some(jmt::Child {
                        version: entry.version,
                        hash: hash_from_bytes(&entry.hash),
                        kind,
                    });
                }
                jmt::Node::Internal(jmt::InternalNode {
                    children: dense,
                    hash: hash_from_bytes(&internal.hash),
                })
            }
            StoredNode::Leaf(leaf) => jmt::Node::Leaf(jmt::LeafNode {
                key: key_from_bytes(&leaf.key),
                value_hash: hash_from_bytes(&leaf.value_hash),
            }),
        }
    }
}

fn hash_from_bytes(bytes: &[u8]) -> jmt::Hash {
    let mut out = [0u8; 32];
    if bytes.len() != 32 {
        panic!("stored hash must be 32 bytes, got {}", bytes.len());
    }
    out.copy_from_slice(bytes);
    out
}

fn key_from_bytes(bytes: &[u8]) -> jmt::Key {
    let mut out = [0u8; 32];
    if bytes.len() != 32 {
        panic!("stored key must be 32 bytes, got {}", bytes.len());
    }
    out.copy_from_slice(bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_jmt::{Blake3Hasher, InternalNode as JmtInternal, LeafNode as JmtLeaf};

    #[test]
    fn roundtrip_leaf() {
        let leaf = jmt::Node::Leaf(JmtLeaf::new([1u8; 32], [2u8; 32]));
        let stored = StoredNode::from_jmt(&leaf);
        let back = stored.to_jmt();
        match (leaf, back) {
            (jmt::Node::Leaf(a), jmt::Node::Leaf(b)) => {
                assert_eq!(a.key, b.key);
                assert_eq!(a.value_hash, b.value_hash);
            }
            _ => panic!("expected leaf"),
        }
    }

    #[test]
    fn roundtrip_internal() {
        // Build a minimal internal node with two children.
        let children: Vec<Option<jmt::Child>> = vec![
            Some(jmt::Child {
                version: 1,
                hash: [0xAA; 32],
                kind: jmt::ChildKind::Leaf,
            }),
            Some(jmt::Child {
                version: 2,
                hash: [0xBB; 32],
                kind: jmt::ChildKind::Internal,
            }),
        ];
        let internal = jmt::Node::Internal(JmtInternal::new::<Blake3Hasher>(children));
        let stored = StoredNode::from_jmt(&internal);
        let back = stored.to_jmt();
        match (&internal, &back) {
            (jmt::Node::Internal(a), jmt::Node::Internal(b)) => {
                assert_eq!(a.hash, b.hash);
                assert_eq!(a.children.len(), b.children.len());
                for (ca, cb) in a.children.iter().zip(b.children.iter()) {
                    assert_eq!(ca.is_some(), cb.is_some());
                    if let (Some(ca), Some(cb)) = (ca, cb) {
                        assert_eq!(ca.version, cb.version);
                        assert_eq!(ca.hash, cb.hash);
                        assert_eq!(ca.kind, cb.kind);
                    }
                }
            }
            _ => panic!("expected internal"),
        }
    }

    #[test]
    fn stored_node_key_roundtrip() {
        let jmt_key = jmt::NodeKey::new(42, jmt::NibblePath::from_key_prefix(&[0xAB; 32], 13));
        let stored = StoredNodeKey::from_jmt(&jmt_key);
        let back = stored.to_jmt().unwrap();
        assert_eq!(jmt_key.version, back.version);
        assert_eq!(jmt_key.path.len(), back.path.len());
        assert_eq!(jmt_key.path.as_bytes(), back.path.as_bytes());
    }

    #[test]
    fn encode_key_sorts_by_version_then_path() {
        let a = encode_key(&StoredNodeKey::from_jmt(&jmt::NodeKey::root(1)));
        let b = encode_key(&StoredNodeKey::from_jmt(&jmt::NodeKey::root(2)));
        assert!(a < b);
    }
}
