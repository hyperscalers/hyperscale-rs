//! [`WaveId`] — self-contained globally unique wave identifier.

use crate::{BlockHeight, Hash, ShardGroupId, WaveIdHash};
use sbor::prelude::*;
use std::collections::BTreeSet;

/// Self-contained wave identifier.
///
/// Globally unique: includes the local shard, block height, and the provision
/// dependency set (remote shards). This eliminates composite `(block_hash, wave_id)`
/// keys throughout the codebase.
///
/// The provision dependency set for a transaction is the set of remote shards
/// it needs state provisions from before execution. Transactions with identical
/// dependency sets belong to the same wave and can be voted on together.
///
/// A wave with empty `remote_shards` represents single-shard transactions.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, BasicSbor)]
pub struct WaveId {
    /// The shard that committed the block containing this wave's transactions.
    pub shard_group_id: ShardGroupId,
    /// Block height at which the wave's transactions were committed.
    pub block_height: BlockHeight,
    /// Set of remote shards the transactions depend on (empty for single-shard waves).
    pub remote_shards: BTreeSet<ShardGroupId>,
}

impl WaveId {
    /// Create a new `WaveId`.
    #[must_use]
    pub const fn new(
        shard_group_id: ShardGroupId,
        block_height: BlockHeight,
        remote_shards: BTreeSet<ShardGroupId>,
    ) -> Self {
        Self {
            shard_group_id,
            block_height,
            remote_shards,
        }
    }

    /// Whether this is a single-shard wave (no remote dependencies).
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.remote_shards.is_empty()
    }

    /// Number of provision source shards.
    #[must_use]
    pub fn dependency_count(&self) -> usize {
        self.remote_shards.len()
    }

    /// Compute a deterministic identity hash for this wave.
    ///
    /// Used for: `BlockManifest` `cert_hashes`, `PendingBlock` matching, storage keys,
    /// wave cert fetch requests. Computable without knowing EC content.
    ///
    /// # Panics
    ///
    /// Panics if SBOR encoding fails — `WaveId` is a closed SBOR type
    /// and encoding is infallible in practice.
    #[must_use]
    pub fn hash(&self) -> WaveIdHash {
        let bytes = basic_encode(self).expect("WaveId serialization should never fail");
        WaveIdHash::from_raw(Hash::from_bytes(&bytes))
    }
}

impl std::fmt::Display for WaveId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_zero() {
            write!(
                f,
                "Wave(shard={}, h={}, ∅)",
                self.shard_group_id.0, self.block_height.0
            )
        } else {
            write!(
                f,
                "Wave(shard={}, h={}, {{",
                self.shard_group_id.0, self.block_height.0
            )?;
            for (i, shard) in self.remote_shards.iter().enumerate() {
                if i > 0 {
                    write!(f, ",")?;
                }
                write!(f, "{}", shard.0)?;
            }
            write!(f, "}})")
        }
    }
}
