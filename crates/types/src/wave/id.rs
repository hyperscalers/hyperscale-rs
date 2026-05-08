//! [`WaveId`] — self-contained globally unique wave identifier.

use std::collections::BTreeSet;
use std::fmt::{self, Display};

use sbor::prelude::*;

use crate::primitives::bloom::BloomKey;
use crate::{BlockHeight, BoundedBTreeSet, Hash, ShardGroupId};

/// Cap on `WaveId.remote_shards` length at decode time.
///
/// A wave's remote shard set is at most `num_shards - 1` (a wave can
/// depend on every other shard). Real deployments run far below this
/// cap; it exists so a peer can't claim a huge dependency set and force
/// the decoder to insert millions of `ShardGroupId`s into a `BTreeSet`
/// before the first frame check fires.
pub const MAX_REMOTE_SHARDS_PER_WAVE: usize = 1024;

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
    shard_group_id: ShardGroupId,
    block_height: BlockHeight,
    remote_shards: BoundedBTreeSet<ShardGroupId, MAX_REMOTE_SHARDS_PER_WAVE>,
}

impl WaveId {
    /// Create a new `WaveId`.
    ///
    /// # Panics
    ///
    /// Panics if `remote_shards.len() > MAX_REMOTE_SHARDS_PER_WAVE`.
    #[must_use]
    pub fn new(
        shard_group_id: ShardGroupId,
        block_height: BlockHeight,
        remote_shards: BTreeSet<ShardGroupId>,
    ) -> Self {
        Self {
            shard_group_id,
            block_height,
            remote_shards: remote_shards.into(),
        }
    }

    /// The shard that committed the block containing this wave's transactions.
    #[must_use]
    pub const fn shard_group_id(&self) -> ShardGroupId {
        self.shard_group_id
    }

    /// Block height at which the wave's transactions were committed.
    #[must_use]
    pub const fn block_height(&self) -> BlockHeight {
        self.block_height
    }

    /// Set of remote shards the transactions depend on (empty for single-shard waves).
    #[must_use]
    pub const fn remote_shards(
        &self,
    ) -> &BoundedBTreeSet<ShardGroupId, MAX_REMOTE_SHARDS_PER_WAVE> {
        &self.remote_shards
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

impl Display for WaveId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_zero() {
            write!(
                f,
                "Wave(shard={}, h={}, ∅)",
                self.shard_group_id.inner(),
                self.block_height.inner()
            )
        } else {
            write!(
                f,
                "Wave(shard={}, h={}, {{",
                self.shard_group_id.inner(),
                self.block_height.inner()
            )?;
            for (i, shard) in self.remote_shards.iter().enumerate() {
                if i > 0 {
                    write!(f, ",")?;
                }
                write!(f, "{}", shard.inner())?;
            }
            write!(f, "}})")
        }
    }
}

#[cfg(test)]
mod tests {
    use sbor::{
        BASIC_SBOR_V1_MAX_DEPTH, BASIC_SBOR_V1_PAYLOAD_PREFIX, Categorize as _, DecodeError,
        Encoder as _, NoCustomValueKind, ValueKind, VecEncoder, basic_decode, basic_encode,
    };

    use super::*;

    fn sample_wave_id() -> WaveId {
        WaveId::new(
            ShardGroupId::new(3),
            BlockHeight::new(42),
            [ShardGroupId::new(1), ShardGroupId::new(7)]
                .into_iter()
                .collect(),
        )
    }

    #[test]
    fn sbor_roundtrip() {
        let wave = sample_wave_id();
        let bytes = basic_encode(&wave).unwrap();
        let decoded: WaveId = basic_decode(&bytes).unwrap();
        assert_eq!(decoded, wave);
    }

    #[test]
    fn sbor_roundtrip_empty_remote_shards() {
        let wave = WaveId::new(ShardGroupId::new(0), BlockHeight::new(1), BTreeSet::new());
        let bytes = basic_encode(&wave).unwrap();
        let decoded: WaveId = basic_decode(&bytes).unwrap();
        assert_eq!(decoded, wave);
    }

    /// Hand-roll a `WaveId` whose `remote_shards` length exceeds the cap and
    /// verify decode rejects it before iterating.
    #[test]
    fn decode_rejects_oversized_remote_shards() {
        let mut buf = Vec::with_capacity(64);
        let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
        enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
            .unwrap();
        enc.write_value_kind(ValueKind::Tuple).unwrap();
        enc.write_size(3).unwrap();
        enc.encode(&ShardGroupId::new(0)).unwrap();
        enc.encode(&BlockHeight::new(0)).unwrap();
        enc.write_value_kind(ValueKind::Array).unwrap();
        enc.write_value_kind(ShardGroupId::value_kind()).unwrap();
        enc.write_size(MAX_REMOTE_SHARDS_PER_WAVE + 1).unwrap();
        let err = basic_decode::<WaveId>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize {
                expected: MAX_REMOTE_SHARDS_PER_WAVE,
                actual,
            } if actual == MAX_REMOTE_SHARDS_PER_WAVE + 1
        ));
    }

    /// SBOR rejects duplicate `BTreeSet` elements at decode time.
    #[test]
    fn decode_rejects_duplicate_remote_shards() {
        let mut buf = Vec::with_capacity(64);
        let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
        enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
            .unwrap();
        enc.write_value_kind(ValueKind::Tuple).unwrap();
        enc.write_size(3).unwrap();
        enc.encode(&ShardGroupId::new(0)).unwrap();
        enc.encode(&BlockHeight::new(0)).unwrap();
        enc.write_value_kind(ValueKind::Array).unwrap();
        enc.write_value_kind(ShardGroupId::value_kind()).unwrap();
        enc.write_size(2).unwrap();
        enc.encode_deeper_body(&ShardGroupId::new(5)).unwrap();
        enc.encode_deeper_body(&ShardGroupId::new(5)).unwrap();
        let err = basic_decode::<WaveId>(&buf).unwrap_err();
        assert!(matches!(err, DecodeError::DuplicateKey));
    }
}
