//! Merkle inclusion proof for cross-shard provisioning.

use sbor::prelude::*;

/// Merkle multiproof authenticating substates' inclusion in the JMT state tree.
///
/// Opaque bytes containing an encoded `hyperscale_jmt::MultiProof`. Encoding,
/// decoding and verification are handled by the storage crate, which owns
/// the adapter between the JMT crate and on-wire SBOR types.
///
/// The proof contains:
/// - Per-claimed-key termination metadata (leaf / empty-subtree / leaf-mismatch)
/// - Sibling hashes for bottom-up verification
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
#[sbor(transparent)]
pub struct MerkleInclusionProof(pub Vec<u8>);

impl MerkleInclusionProof {
    /// Create a new proof from raw bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get the raw proof bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Create a dummy (empty) proof for testing.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn dummy() -> Self {
        Self(Vec::new())
    }
}
