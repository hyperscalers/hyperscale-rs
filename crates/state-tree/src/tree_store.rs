//! Storage traits and types for the verkle state tree.
//!
//! Defines the physical representation of tree nodes (SBOR-serializable newtypes
//! wrapping JVT types), storage traits, and key encoding for RocksDB.

use std::collections::HashMap;
use std::sync::RwLock;

use hyperscale_types::Hash;
use jellyfish_verkle_tree as jvt;
use jvt::commitment::commitment_to_field;
use sbor::prelude::*;

/// Version = block height.
pub type Version = u64;

// ─── Stored node key ────────────────────────────────────────────────────

/// A globally unique key for a tree node, combining a tier prefix with
/// the JVT node's version and byte path.
///
/// The tier prefix namespaces nodes from different tiers within the same
/// RocksDB column family:
/// - Entity tier: empty prefix
/// - Partition tier: `entity_key_bytes ++ SEPARATOR`
/// - Substate tier: `entity_key_bytes ++ SEPARATOR ++ partition_num ++ SEPARATOR`
#[derive(
    Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, BasicCategorize, BasicEncode, BasicDecode,
)]
pub struct StoredNodeKey {
    version: Version,
    /// Tier prefix bytes + JVT byte_path, concatenated.
    full_path: Vec<u8>,
}

impl StoredNodeKey {
    /// Create from a JVT NodeKey (no prefix — flat tree).
    pub fn from_jvt(node_key: &jvt::NodeKey) -> Self {
        Self {
            version: node_key.version,
            full_path: node_key.byte_path().to_vec(),
        }
    }

    /// Convert back to a JVT NodeKey.
    pub fn to_jvt(&self) -> jvt::NodeKey {
        jvt::NodeKey::new(self.version, &self.full_path)
    }

    pub fn version(&self) -> Version {
        self.version
    }

    pub fn full_path(&self) -> &[u8] {
        &self.full_path
    }

    /// Construct a child node key by appending an index byte to the path.
    pub fn child_key(&self, child_version: u64, child_index: u8) -> Self {
        let mut child_path = self.full_path.clone();
        child_path.push(child_index);
        Self {
            version: child_version,
            full_path: child_path,
        }
    }
}

/// Encode a `StoredNodeKey` for use as a RocksDB key.
///
/// Format: `[version_8B_be][path_len_1B][full_path_bytes]`
///
/// Version-first ordering ensures nodes from the same block are adjacent,
/// which is friendly for LSM-tree compaction and range deletes during pruning.
pub fn encode_key(key: &StoredNodeKey) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + 1 + key.full_path.len());
    buf.extend_from_slice(&key.version.to_be_bytes());
    buf.push(key.full_path.len() as u8);
    buf.extend_from_slice(&key.full_path);
    buf
}

// ─── Stored node types (SBOR-serializable) ──────────────────────────────

/// Versioned wrapper for schema evolution.
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

/// Physical tree node representation for persistence.
///
/// This is the SBOR-serializable mirror of `jvt::Node`. Commitments are stored
/// as 64-byte uncompressed curve points (x, y coordinates) to avoid expensive
/// field inversion + square root on every read.
#[derive(Clone, PartialEq, Eq, Hash, Debug, BasicCategorize, BasicEncode, BasicDecode)]
pub enum StoredNode {
    Internal(StoredInternalNode),
    EaS(StoredEaSNode),
}

/// An internal node with up to 256 children.
#[derive(Clone, PartialEq, Eq, Hash, Debug, BasicCategorize, BasicEncode, BasicDecode)]
pub struct StoredInternalNode {
    pub children: Vec<StoredChildEntry>,
    /// Pedersen vector commitment, uncompressed (64 bytes: x || y).
    pub commitment: Vec<u8>,
}

/// A child reference in an internal node.
#[derive(Clone, PartialEq, Eq, Hash, Debug, BasicCategorize, BasicEncode, BasicDecode)]
pub struct StoredChildEntry {
    pub index: u8,
    pub version: u64,
    pub commitment: Vec<u8>,
    /// Pre-computed `commitment_to_field` result. Stored to avoid expensive
    /// EC field inversion on every read.
    pub field: Vec<u8>,
}

/// Extension-and-Suffix (EaS) node.
#[derive(Clone, PartialEq, Eq, Hash, Debug, BasicCategorize, BasicEncode, BasicDecode)]
pub struct StoredEaSNode {
    pub stem: Vec<u8>,
    /// Sparse (suffix, field_element_bytes) pairs, sorted by suffix.
    /// Values are pre-hashed field elements (32 bytes each), not raw substate bytes.
    pub values: Vec<(u8, Vec<u8>)>,
    pub c1: Vec<u8>,
    pub c2: Vec<u8>,
    pub extension_commitment: Vec<u8>,
}

/// A part of the tree that has become stale and needs pruning.
#[derive(Clone, PartialEq, Eq, Hash, Debug, BasicCategorize, BasicEncode, BasicDecode)]
pub enum StaleTreePart {
    /// A single node.
    Node(StoredNodeKey),
    /// An entire subtree rooted at this key.
    Subtree(StoredNodeKey),
}

// ─── Commitment serialization helpers ───────────────────────────────────

use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, Fr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// Serialize a commitment as uncompressed (64 bytes: x || y).
/// No field inversion — just two coordinate writes.
fn commitment_to_bytes(c: jvt::Commitment) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    c.0.serialize_uncompressed(&mut buf)
        .expect("Bandersnatch point serialization should never fail");
    buf
}

/// Deserialize a commitment from uncompressed bytes (64 bytes: x || y).
/// No field inversion or square root — just two coordinate reads + on-curve check.
fn bytes_to_commitment(bytes: &[u8]) -> jvt::Commitment {
    jvt::Commitment(
        EdwardsAffine::deserialize_uncompressed(bytes)
            .expect("stored commitment bytes should be valid"),
    )
}

/// Serialize a field element to 32 bytes.
fn field_element_to_bytes(fe: jvt::commitment::FieldElement) -> Vec<u8> {
    use ark_serialize::CanonicalSerialize;
    let mut buf = vec![0u8; 32];
    fe.0.serialize_compressed(&mut buf[..])
        .expect("field element serialization should never fail");
    buf
}

/// Deserialize a field element from 32 bytes.
///
/// Must use `deserialize_compressed` to match `field_element_to_bytes` which uses
/// `serialize_compressed`. Using `from_le_bytes_mod_order` would silently corrupt
/// the value (it reduces mod p, which is not the inverse of canonical serialization).
fn bytes_to_field_element(bytes: &[u8]) -> jvt::commitment::FieldElement {
    jvt::commitment::FieldElement(
        Fr::deserialize_compressed(bytes).expect("stored field element bytes should be valid"),
    )
}

/// Convert a JVT commitment to a hyperscale Hash (for state root, value hashes).
///
/// Uses compressed serialization (32 bytes) for the consensus-visible identity.
/// This is separate from the storage format (uncompressed) — the hash is what
/// goes into block headers and QCs.
pub fn commitment_to_hash(c: jvt::Commitment) -> Hash {
    let mut buf = [0u8; 32];
    c.0.serialize_compressed(&mut buf[..])
        .expect("Bandersnatch point serialization should never fail");
    Hash::from_hash_bytes(&buf)
}

// ─── JVT ↔ Stored conversions ──────────────────────────────────────────

impl StoredNode {
    /// Convert from a JVT node.
    pub fn from_jvt(node: &jvt::Node) -> Self {
        match node {
            jvt::Node::Internal(internal) => {
                let mut children: Vec<StoredChildEntry> = internal
                    .children
                    .iter()
                    .map(|(&idx, child)| StoredChildEntry {
                        index: idx,
                        version: child.version,
                        commitment: commitment_to_bytes(child.commitment),
                        field: field_element_to_bytes(child.field),
                    })
                    .collect();
                children.sort_by_key(|c| c.index);
                StoredNode::Internal(StoredInternalNode {
                    children,
                    commitment: commitment_to_bytes(internal.commitment),
                })
            }
            jvt::Node::EaS(eas) => {
                let mut values: Vec<(u8, Vec<u8>)> = eas
                    .values
                    .iter()
                    .map(|(&suffix, val)| (suffix, field_element_to_bytes(*val)))
                    .collect();
                values.sort_by_key(|(k, _)| *k);
                StoredNode::EaS(StoredEaSNode {
                    stem: eas.stem.clone(),
                    values,
                    c1: commitment_to_bytes(eas.c1),
                    c2: commitment_to_bytes(eas.c2),
                    extension_commitment: commitment_to_bytes(eas.extension_commitment),
                })
            }
        }
    }

    /// Convert back to a JVT node.
    ///
    /// Constructs nodes directly from stored commitments and cached field elements.
    /// No `commitment_to_field` calls for internal node children — the field values
    /// are pre-stored.
    pub fn to_jvt(&self) -> jvt::Node {
        match self {
            StoredNode::Internal(internal) => {
                let children: HashMap<u8, jvt::Child> = internal
                    .children
                    .iter()
                    .map(|entry| {
                        let commitment = bytes_to_commitment(&entry.commitment);
                        let field = bytes_to_field_element(&entry.field);
                        (
                            entry.index,
                            jvt::Child::new_with_field(entry.version, commitment, field),
                        )
                    })
                    .collect();
                jvt::Node::Internal(jvt::InternalNode {
                    children,
                    commitment: bytes_to_commitment(&internal.commitment),
                })
            }
            StoredNode::EaS(eas) => {
                let values: HashMap<u8, jvt::Value> = eas
                    .values
                    .iter()
                    .map(|(suffix, fe_bytes)| (*suffix, bytes_to_field_element(fe_bytes)))
                    .collect();
                let c1 = bytes_to_commitment(&eas.c1);
                let c2 = bytes_to_commitment(&eas.c2);
                jvt::Node::EaS(Box::new(jvt::EaSNode {
                    stem: eas.stem.clone(),
                    values,
                    c1,
                    c2,
                    c1_field: commitment_to_field(c1),
                    c2_field: commitment_to_field(c2),
                    extension_commitment: bytes_to_commitment(&eas.extension_commitment),
                }))
            }
        }
    }
}

// ─── Storage traits ─────────────────────────────────────────────────────

/// Read-only access to stored tree nodes.
pub trait ReadableTreeStore {
    fn get_node(&self, key: &StoredNodeKey) -> Option<StoredNode>;

    /// Batch-fetch multiple nodes at once. Default falls back to individual gets.
    /// Override this for storage backends that support batch reads (e.g. RocksDB multi_get).
    fn get_nodes_batch(&self, keys: &[StoredNodeKey]) -> Vec<Option<StoredNode>> {
        keys.iter().map(|k| self.get_node(k)).collect()
    }
}

/// Write access to stored tree nodes.
pub trait WriteableTreeStore {
    fn insert_node(&self, key: StoredNodeKey, node: StoredNode);
    fn record_stale_tree_part(&self, part: StaleTreePart);
}

// ─── In-memory implementation ───────────────────────────────────────────

/// In-memory tree store for tests and simulation.
#[derive(Debug)]
pub struct TypedInMemoryTreeStore {
    pub tree_nodes: RwLock<HashMap<StoredNodeKey, StoredNode>>,
    pub stale_part_buffer: RwLock<Vec<StaleTreePart>>,
    pub pruning_enabled: bool,
}

impl TypedInMemoryTreeStore {
    pub fn new() -> Self {
        Self {
            tree_nodes: RwLock::new(HashMap::new()),
            stale_part_buffer: RwLock::new(Vec::new()),
            pruning_enabled: false,
        }
    }

    pub fn with_pruning_enabled(self) -> Self {
        Self {
            pruning_enabled: true,
            ..self
        }
    }
}

impl Default for TypedInMemoryTreeStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ReadableTreeStore for TypedInMemoryTreeStore {
    fn get_node(&self, key: &StoredNodeKey) -> Option<StoredNode> {
        self.tree_nodes.read().unwrap().get(key).cloned()
    }
}

impl WriteableTreeStore for TypedInMemoryTreeStore {
    fn insert_node(&self, key: StoredNodeKey, node: StoredNode) {
        self.tree_nodes.write().unwrap().insert(key, node);
    }

    fn record_stale_tree_part(&self, part: StaleTreePart) {
        if self.pruning_enabled {
            match part {
                StaleTreePart::Node(node_key) => {
                    self.tree_nodes.write().unwrap().remove(&node_key);
                }
                StaleTreePart::Subtree(node_key) => {
                    // For pruning, just remove the root. A more thorough impl
                    // would walk the subtree, but for now this is sufficient.
                    self.tree_nodes.write().unwrap().remove(&node_key);
                }
            }
        } else {
            self.stale_part_buffer.write().unwrap().push(part);
        }
    }
}
