// Forked from radixdlt-scrypto (originally from Aptos). Modified to use Blake3 and BasicSbor.

use super::tier_framework::StoredNode;
// Re-exports
pub use super::types::{Nibble, NibblePath, TreeNodeKey, Version};
use super::{Node, StorageError, TreeReader};
use hyperscale_codec as sbor;
use hyperscale_codec::prelude::*;
use hyperscale_types::Hash;
use std::collections::{HashMap, VecDeque};
use std::sync::RwLock;

#[derive(Clone, PartialEq, Eq, Hash, Debug, BasicCategorize, BasicEncode, BasicDecode)]
pub enum VersionedTreeNode {
    V1(TreeNode),
}

impl From<TreeNode> for VersionedTreeNode {
    fn from(node: TreeNode) -> Self {
        Self::V1(node)
    }
}

impl From<VersionedTreeNode> for TreeNode {
    fn from(v: VersionedTreeNode) -> Self {
        match v {
            VersionedTreeNode::V1(n) => n,
        }
    }
}

impl VersionedTreeNode {
    /// Construct from the latest (current) version.
    pub fn from_latest_version(node: TreeNode) -> Self {
        Self::V1(node)
    }

    /// Unwrap into the latest version, applying any migrations.
    pub fn fully_update_and_into_latest_version(self) -> TreeNode {
        match self {
            Self::V1(n) => n,
        }
    }
}

/// A physical tree node, to be used in the storage.
#[derive(Clone, PartialEq, Eq, Hash, Debug, BasicCategorize, BasicEncode, BasicDecode)]
pub enum TreeNode {
    /// Internal node - always metadata-only, as per JMT design.
    Internal(TreeInternalNode),
    /// Leaf node.
    Leaf(TreeLeafNode),
    /// An "empty tree" indicator, which may only be used as a root.
    Null,
}

/// Internal node.
#[derive(Clone, PartialEq, Eq, Hash, Debug, BasicCategorize, BasicEncode, BasicDecode)]
pub struct TreeInternalNode {
    /// Metadata of each existing child.
    pub children: Vec<TreeChildEntry>,
}

/// Child node metadata.
#[derive(Clone, PartialEq, Eq, Hash, Debug, BasicCategorize, BasicEncode, BasicDecode)]
pub struct TreeChildEntry {
    /// First of the remaining nibbles in the key.
    pub nibble: Nibble,
    /// State version at which this child's node was created.
    pub version: u64,
    /// Cached child hash (i.e. needed only for performance).
    pub hash: Hash,
    /// Number of leaves under this child. A value of 1 with a leaf node type
    /// indicates a direct leaf child; higher values indicate an internal subtree.
    pub leaf_count: usize,
}

/// Leaf node.
#[derive(Clone, PartialEq, Eq, Hash, Debug, BasicCategorize, BasicEncode, BasicDecode)]
pub struct TreeLeafNode {
    /// All the remaining nibbles in the _hashed_ payload's key.
    pub key_suffix: NibblePath,
    /// An externally-provided hash of the payload.
    pub value_hash: Hash,
    /// A version at which the [`value_hash`] has most recently changed.
    pub last_hash_change_version: Version,
}

/// A part of a tree that may become stale (i.e. need eventual pruning).
#[derive(Clone, PartialEq, Eq, Hash, Debug, BasicCategorize, BasicEncode, BasicDecode)]
pub enum StaleTreePart {
    /// A single node to be removed.
    Node(StoredTreeNodeKey),
    /// An entire subtree of descendants of a specific node (including itself).
    Subtree(StoredTreeNodeKey),
}

/// A global tree node key, made collision-free from other layers
#[derive(
    Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, BasicCategorize, BasicEncode, BasicDecode,
)]
pub struct StoredTreeNodeKey {
    // The version at which the node is created.
    version: Version,
    // The nibble path this node represents in the tree.
    nibble_path: NibblePath,
}

impl StoredTreeNodeKey {
    pub fn new(version: Version, nibble_path: NibblePath) -> Self {
        Self {
            version,
            nibble_path,
        }
    }

    pub fn unprefixed(local_node_key: TreeNodeKey) -> Self {
        let (version, nibble_path) = local_node_key.into();
        Self {
            version,
            nibble_path,
        }
    }

    pub fn prefixed(prefix_bytes: &[u8], local_node_key: &TreeNodeKey) -> Self {
        Self {
            version: local_node_key.version(),
            nibble_path: local_node_key.nibble_path().prefix_with(prefix_bytes),
        }
    }

    /// Gets the version.
    pub fn version(&self) -> Version {
        self.version
    }

    /// Gets the nibble path.
    pub fn nibble_path(&self) -> &NibblePath {
        &self.nibble_path
    }

    /// Generates a child node key based on this node key.
    pub fn gen_child_node_key(&self, version: Version, n: Nibble) -> Self {
        let mut node_nibble_path = self.nibble_path().clone();
        node_nibble_path.push(n);
        Self::new(version, node_nibble_path)
    }

    /// Generates parent node key at the same version based on this node key.
    pub fn gen_parent_node_key(&self) -> Self {
        let mut node_nibble_path = self.nibble_path().clone();
        assert!(
            node_nibble_path.pop().is_some(),
            "Current node key is root.",
        );
        Self::new(self.version, node_nibble_path)
    }
}

impl From<StoredTreeNodeKey> for (Version, NibblePath) {
    fn from(value: StoredTreeNodeKey) -> Self {
        (value.version, value.nibble_path)
    }
}

/// The "read" part of a physical tree node storage SPI.
pub trait ReadableTreeStore {
    /// Gets node by key, if it exists.
    fn get_node(&self, global_key: &StoredTreeNodeKey) -> Option<TreeNode>;
}

/// The "write" part of a physical tree node storage SPI.
pub trait WriteableTreeStore {
    /// Inserts the node under a new, unique key (i.e. never an update).
    fn insert_node(&self, global_key: StoredTreeNodeKey, node: TreeNode);

    /// Marks the given tree part for a (potential) future removal by an arbitrary external pruning
    /// process.
    fn record_stale_tree_part(&self, global_tree_part: StaleTreePart);
}

/// A `TreeStore` based on memory object copies (i.e. no serialization).
#[derive(Debug)]
pub struct TypedInMemoryTreeStore {
    pub tree_nodes: RwLock<HashMap<StoredTreeNodeKey, TreeNode>>,
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

// This implementation allows interpreting the TypedInMemoryTreeStore as a single store
impl TreeReader<Version> for TypedInMemoryTreeStore {
    fn get_node_option(
        &self,
        node_key: &TreeNodeKey,
    ) -> Result<Option<Node<Version>>, StorageError> {
        Ok(
            ReadableTreeStore::get_node(self, &StoredTreeNodeKey::unprefixed(node_key.clone()))
                .map(|tree_node| tree_node.into_jmt_node(node_key)),
        )
    }
}

impl ReadableTreeStore for TypedInMemoryTreeStore {
    fn get_node(&self, key: &StoredTreeNodeKey) -> Option<TreeNode> {
        self.tree_nodes.read().unwrap().get(key).cloned()
    }
}

impl WriteableTreeStore for TypedInMemoryTreeStore {
    fn insert_node(&self, key: StoredTreeNodeKey, node: TreeNode) {
        self.tree_nodes.write().unwrap().insert(key, node);
    }

    fn record_stale_tree_part(&self, part: StaleTreePart) {
        if self.pruning_enabled {
            match part {
                StaleTreePart::Node(node_key) => {
                    self.tree_nodes.write().unwrap().remove(&node_key);
                }
                StaleTreePart::Subtree(node_key) => {
                    let mut queue = VecDeque::new();
                    queue.push_back(node_key);

                    while let Some(node_key) = queue.pop_front() {
                        if let Some(value) = self.tree_nodes.write().unwrap().remove(&node_key) {
                            match value {
                                TreeNode::Internal(x) => {
                                    for child in x.children {
                                        queue.push_back(
                                            node_key
                                                .gen_child_node_key(child.version, child.nibble),
                                        )
                                    }
                                }
                                TreeNode::Leaf(_) => {}
                                TreeNode::Null => {}
                            }
                        }
                    }
                }
            }
        } else {
            self.stale_part_buffer.write().unwrap().push(part);
        }
    }
}

/// Encodes the given node key in a format friendly to Level-like databases (i.e. strictly ordered
/// by numeric version).
pub fn encode_key(key: &StoredTreeNodeKey) -> Vec<u8> {
    let version_bytes = &key.version().to_be_bytes();
    let nibble_path_bytes = key.nibble_path().bytes();
    let parity_byte = &[(key.nibble_path().num_nibbles() % 2) as u8; 1];
    [version_bytes, nibble_path_bytes, parity_byte].concat()
}
