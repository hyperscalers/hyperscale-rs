//! [`WaveId`] — self-contained globally unique wave identifier.

use std::collections::BTreeSet;
use std::fmt::{self, Display};

use sbor::prelude::*;
use sbor::{
    Categorize, Decode, DecodeError, Decoder, Describe, Encode, EncodeError, Encoder,
    NoCustomTypeKind, NoCustomValueKind, RustTypeId, TypeData, TypeKind, ValueKind,
};

use crate::primitives::bloom::BloomKey;
use crate::sbor_codec::decode_bounded_btree_set;
use crate::{BlockHeight, Hash, ShardGroupId};

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
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
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

impl<E: Encoder<NoCustomValueKind>> Encode<NoCustomValueKind, E> for WaveId {
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_value_kind(ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_size(3)?;
        encoder.encode(&self.shard_group_id)?;
        encoder.encode(&self.block_height)?;
        encoder.encode(&self.remote_shards)?;
        Ok(())
    }
}

impl<D: Decoder<NoCustomValueKind>> Decode<NoCustomValueKind, D> for WaveId {
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: ValueKind<NoCustomValueKind>,
    ) -> Result<Self, DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, ValueKind::Tuple)?;
        let length = decoder.read_size()?;
        if length != 3 {
            return Err(DecodeError::UnexpectedSize {
                expected: 3,
                actual: length,
            });
        }
        let shard_group_id: ShardGroupId = decoder.decode()?;
        let block_height: BlockHeight = decoder.decode()?;
        let remote_shards =
            decode_bounded_btree_set::<_, ShardGroupId>(decoder, MAX_REMOTE_SHARDS_PER_WAVE)?;
        Ok(Self {
            shard_group_id,
            block_height,
            remote_shards,
        })
    }
}

impl Categorize<NoCustomValueKind> for WaveId {
    fn value_kind() -> ValueKind<NoCustomValueKind> {
        ValueKind::Tuple
    }
}

impl Describe<NoCustomTypeKind> for WaveId {
    const TYPE_ID: RustTypeId = RustTypeId::novel_with_code("WaveId", &[], &[]);

    fn type_data() -> TypeData<NoCustomTypeKind, RustTypeId> {
        TypeData::unnamed(TypeKind::Any)
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

#[cfg(test)]
mod tests {
    use sbor::{
        BASIC_SBOR_V1_MAX_DEPTH, BASIC_SBOR_V1_PAYLOAD_PREFIX, VecEncoder, basic_decode,
        basic_encode,
    };

    use super::*;

    fn sample_wave_id() -> WaveId {
        WaveId {
            shard_group_id: ShardGroupId(3),
            block_height: BlockHeight(42),
            remote_shards: [ShardGroupId(1), ShardGroupId(7)].into_iter().collect(),
        }
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
        let wave = WaveId {
            shard_group_id: ShardGroupId(0),
            block_height: BlockHeight(1),
            remote_shards: BTreeSet::new(),
        };
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
        enc.encode(&ShardGroupId(0)).unwrap();
        enc.encode(&BlockHeight(0)).unwrap();
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

    /// SBOR rejects duplicate `BTreeSet` elements at decode time; preserve
    /// that behavior across the manual impl.
    #[test]
    fn decode_rejects_duplicate_remote_shards() {
        let mut buf = Vec::with_capacity(64);
        let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
        enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
            .unwrap();
        enc.write_value_kind(ValueKind::Tuple).unwrap();
        enc.write_size(3).unwrap();
        enc.encode(&ShardGroupId(0)).unwrap();
        enc.encode(&BlockHeight(0)).unwrap();
        enc.write_value_kind(ValueKind::Array).unwrap();
        enc.write_value_kind(ShardGroupId::value_kind()).unwrap();
        enc.write_size(2).unwrap();
        enc.encode_deeper_body(&ShardGroupId(5)).unwrap();
        enc.encode_deeper_body(&ShardGroupId(5)).unwrap();
        let err = basic_decode::<WaveId>(&buf).unwrap_err();
        assert!(matches!(err, DecodeError::DuplicateKey));
    }
}
