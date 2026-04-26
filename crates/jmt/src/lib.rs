//! Binary Jellyfish Merkle Tree — a versioned authenticated data
//! structure with batched multiproofs.
//!
//! Generic over:
//! - **Hash function** (default [`Blake3Hasher`]; designed to accommodate
//!   Poseidon2 or other 32-byte-output hashes for ZK use later).
//! - **Arity** via `const ARITY_BITS: u8` (default `1`, i.e. binary).
//!   Larger arity reduces tree depth at the cost of per-level sibling
//!   count in multiproofs.
//!
//! # Public API
//!
//! All operations are stateless — storage is abstracted via
//! [`TreeReader`] / [`TreeWriter`]. Callers drive commits by applying
//! the returned [`UpdateResult`] to their store.
//!
//! ```ignore
//! use hyperscale_jmt::{Blake3Hasher, MemoryStore, Tree};
//!
//! type Jmt = Tree<Blake3Hasher>; // binary, Blake3
//!
//! let mut store = MemoryStore::new();
//! let updates = [([0u8; 32], Some([1u8; 32]))].into_iter().collect();
//! let result = Jmt::apply_updates(&store, None, 1, updates).unwrap();
//! store.apply(&result);
//! ```

pub mod hasher;
pub mod multiproof;
pub mod node;
pub mod storage;
pub mod tree;

pub use hasher::{Blake3Hasher, EMPTY_HASH, Hash, Hasher};
pub use multiproof::{ClaimTermination, DecodeError, MultiProof, ProofClaim, ProofError};
pub use node::{
    Child, ChildKind, InternalNode, Key, LeafNode, NibblePath, Node, NodeKey, PathDecodeError,
    StaleNodeIndex, TreeUpdateBatch, ValueHash,
};
pub use storage::{MemoryStore, TreeReader, TreeWriter};
pub use tree::{Tree, UpdateError, UpdateResult};
