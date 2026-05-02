//! [`WaveId`] — self-contained globally unique wave identifier.

use crate::primitives::bloom::BloomKey;
use crate::{BlockHeight, Hash, ShardGroupId};
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
}

impl BloomKey for WaveId {
    fn bloom_seed(&self) -> [u8; 16] {
        let bytes = basic_encode(self).expect("WaveId serialization should never fail");
        let h = Hash::from_bytes(&bytes);
        let raw = h.as_bytes();
        let mut out = [0u8; 16];
        out.copy_from_slice(&raw[0..16]);
        out
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
