//! Per-validator [`ExecutionVote`] over an entire wave's transactions.

use sbor::prelude::*;
use sbor::{
    Categorize, Decode, DecodeError, Decoder, Describe, Encode, EncodeError, Encoder,
    NoCustomTypeKind, NoCustomValueKind, RustTypeId, TypeData, TypeKind, ValueKind,
};

use crate::sbor_codec::decode_bounded_vec;
use crate::{
    BlockHash, BlockHeight, Bls12381G2Signature, GlobalReceiptRoot, MAX_TXS_PER_BLOCK,
    ShardGroupId, TxOutcome, ValidatorId, WaveId, WeightedTimestamp,
};

/// A validator's vote on all transactions in an execution wave.
///
/// One vote covers all transactions sharing the same provision dependency set,
/// with `global_receipt_root` being a padded merkle root over per-tx leaf hashes
/// where each leaf = `H(tx_hash` || `receipt_hash` || `success_byte`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionVote {
    block_hash: BlockHash,
    block_height: BlockHeight,
    vote_anchor_ts: WeightedTimestamp,
    wave_id: WaveId,
    shard_group_id: ShardGroupId,
    global_receipt_root: GlobalReceiptRoot,
    tx_count: u32,
    tx_outcomes: Vec<TxOutcome>,
    validator: ValidatorId,
    signature: Bls12381G2Signature,
}

impl ExecutionVote {
    /// Build an `ExecutionVote` from its parts.
    #[allow(clippy::too_many_arguments)] // mirrors the 10 stored fields
    #[must_use]
    pub const fn new(
        block_hash: BlockHash,
        block_height: BlockHeight,
        vote_anchor_ts: WeightedTimestamp,
        wave_id: WaveId,
        shard_group_id: ShardGroupId,
        global_receipt_root: GlobalReceiptRoot,
        tx_count: u32,
        tx_outcomes: Vec<TxOutcome>,
        validator: ValidatorId,
        signature: Bls12381G2Signature,
    ) -> Self {
        Self {
            block_hash,
            block_height,
            vote_anchor_ts,
            wave_id,
            shard_group_id,
            global_receipt_root,
            tx_count,
            tx_outcomes,
            validator,
            signature,
        }
    }

    /// Block this wave belongs to.
    #[must_use]
    pub const fn block_hash(&self) -> BlockHash {
        self.block_hash
    }

    /// Block height (the block containing the wave's transactions).
    #[must_use]
    pub const fn block_height(&self) -> BlockHeight {
        self.block_height
    }

    /// BFT-authenticated anchor at which this vote was cast.
    ///
    /// Validators vote at each block commit where the wave is complete.
    /// Including `vote_anchor_ts` in the BLS-signed message prevents
    /// cross-height aggregation, ensuring that if an abort intent changes
    /// the `global_receipt_root` between heights, stale votes cannot combine.
    #[must_use]
    pub const fn vote_anchor_ts(&self) -> WeightedTimestamp {
        self.vote_anchor_ts
    }

    /// Which wave within the block.
    #[must_use]
    pub const fn wave_id(&self) -> &WaveId {
        &self.wave_id
    }

    /// Which shard produced this vote.
    #[must_use]
    pub const fn shard_group_id(&self) -> ShardGroupId {
        self.shard_group_id
    }

    /// Merkle root over per-tx outcome leaves.
    #[must_use]
    pub const fn global_receipt_root(&self) -> GlobalReceiptRoot {
        self.global_receipt_root
    }

    /// Number of transactions in this wave.
    #[must_use]
    pub const fn tx_count(&self) -> u32 {
        self.tx_count
    }

    /// Per-tx execution outcomes in wave order.
    ///
    /// Carried alongside the vote so any aggregator can extract `tx_outcomes`
    /// directly from quorum votes when building the EC. Not included in the
    /// BLS-signed message (`global_receipt_root` already commits to the content).
    /// This avoids relying on each aggregator's local accumulator, which may
    /// have diverged due to different abort timing.
    #[must_use]
    pub const fn tx_outcomes(&self) -> &Vec<TxOutcome> {
        &self.tx_outcomes
    }

    /// Validator who cast this vote.
    #[must_use]
    pub const fn validator(&self) -> ValidatorId {
        self.validator
    }

    /// BLS signature over the vote signing message.
    #[must_use]
    pub const fn signature(&self) -> Bls12381G2Signature {
        self.signature
    }

    /// Decompose into the raw fields, in struct-declaration order.
    #[allow(clippy::type_complexity)] // mirrors the 10 stored fields
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        BlockHash,
        BlockHeight,
        WeightedTimestamp,
        WaveId,
        ShardGroupId,
        GlobalReceiptRoot,
        u32,
        Vec<TxOutcome>,
        ValidatorId,
        Bls12381G2Signature,
    ) {
        (
            self.block_hash,
            self.block_height,
            self.vote_anchor_ts,
            self.wave_id,
            self.shard_group_id,
            self.global_receipt_root,
            self.tx_count,
            self.tx_outcomes,
            self.validator,
            self.signature,
        )
    }
}

impl<E: Encoder<NoCustomValueKind>> Encode<NoCustomValueKind, E> for ExecutionVote {
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_value_kind(ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_size(9)?;
        encoder.encode(&self.block_hash)?;
        encoder.encode(&self.block_height)?;
        encoder.encode(&self.vote_anchor_ts)?;
        encoder.encode(&self.wave_id)?;
        encoder.encode(&self.shard_group_id)?;
        encoder.encode(&self.global_receipt_root)?;
        encoder.encode(&self.tx_count)?;
        encoder.encode(&self.tx_outcomes)?;
        encoder.encode(&self.validator)?;
        encoder.encode(&self.signature)
    }
}

impl<D: Decoder<NoCustomValueKind>> Decode<NoCustomValueKind, D> for ExecutionVote {
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: ValueKind<NoCustomValueKind>,
    ) -> Result<Self, DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, ValueKind::Tuple)?;
        let length = decoder.read_size()?;
        if length != 9 {
            return Err(DecodeError::UnexpectedSize {
                expected: 9,
                actual: length,
            });
        }
        let block_hash: BlockHash = decoder.decode()?;
        let block_height: BlockHeight = decoder.decode()?;
        let vote_anchor_ts: WeightedTimestamp = decoder.decode()?;
        let wave_id: WaveId = decoder.decode()?;
        let shard_group_id: ShardGroupId = decoder.decode()?;
        let global_receipt_root: GlobalReceiptRoot = decoder.decode()?;
        let tx_count: u32 = decoder.decode()?;
        let tx_outcomes = decode_bounded_vec::<_, TxOutcome>(decoder, MAX_TXS_PER_BLOCK)?;
        let validator: ValidatorId = decoder.decode()?;
        let signature: Bls12381G2Signature = decoder.decode()?;
        Ok(Self {
            block_hash,
            block_height,
            vote_anchor_ts,
            wave_id,
            shard_group_id,
            global_receipt_root,
            tx_count,
            tx_outcomes,
            validator,
            signature,
        })
    }
}

impl Categorize<NoCustomValueKind> for ExecutionVote {
    fn value_kind() -> ValueKind<NoCustomValueKind> {
        ValueKind::Tuple
    }
}

impl Describe<NoCustomTypeKind> for ExecutionVote {
    const TYPE_ID: RustTypeId = RustTypeId::novel_with_code("ExecutionVote", &[], &[]);

    fn type_data() -> TypeData<NoCustomTypeKind, RustTypeId> {
        TypeData::unnamed(TypeKind::Any)
    }
}

#[cfg(test)]
mod tests {
    use sbor::{
        BASIC_SBOR_V1_MAX_DEPTH, BASIC_SBOR_V1_PAYLOAD_PREFIX, VecEncoder, basic_decode,
        basic_encode,
    };

    use super::*;
    use crate::{ExecutionOutcome, GlobalReceiptHash, Hash, TxHash};

    fn sample_outcome(seed: u8) -> TxOutcome {
        TxOutcome::new(
            TxHash::from_raw(Hash::from_bytes(&[seed; 4])),
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(&[seed + 1; 4])),
            },
        )
    }

    fn sample_vote() -> ExecutionVote {
        let outcomes = vec![sample_outcome(1), sample_outcome(2)];
        ExecutionVote::new(
            BlockHash::from_raw(Hash::from_bytes(b"block")),
            BlockHeight::new(7),
            WeightedTimestamp::from_millis(11),
            WaveId::new(
                ShardGroupId::new(0),
                BlockHeight::new(7),
                std::iter::once(ShardGroupId::new(1)).collect(),
            ),
            ShardGroupId::new(0),
            GlobalReceiptRoot::from_raw(Hash::from_bytes(b"root")),
            u32::try_from(outcomes.len()).unwrap(),
            outcomes,
            ValidatorId::new(3),
            Bls12381G2Signature([0u8; 96]),
        )
    }

    #[test]
    fn sbor_roundtrip() {
        let vote = sample_vote();
        let bytes = basic_encode(&vote).unwrap();
        let decoded: ExecutionVote = basic_decode(&bytes).unwrap();
        assert_eq!(decoded, vote);
    }

    /// Hand-roll a vote whose `tx_outcomes` count exceeds the cap and verify
    /// decode rejects it before iterating.
    #[test]
    fn decode_rejects_oversized_tx_outcomes() {
        let vote = sample_vote();
        let mut buf = Vec::with_capacity(128);
        let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
        enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
            .unwrap();
        enc.write_value_kind(ValueKind::Tuple).unwrap();
        enc.write_size(9).unwrap();
        enc.encode(&vote.block_hash).unwrap();
        enc.encode(&vote.block_height).unwrap();
        enc.encode(&vote.vote_anchor_ts).unwrap();
        enc.encode(&vote.wave_id).unwrap();
        enc.encode(&vote.shard_group_id).unwrap();
        enc.encode(&vote.global_receipt_root).unwrap();
        enc.encode(&vote.tx_count).unwrap();
        enc.write_value_kind(ValueKind::Array).unwrap();
        enc.write_value_kind(TxOutcome::value_kind()).unwrap();
        enc.write_size(MAX_TXS_PER_BLOCK + 1).unwrap();
        let err = basic_decode::<ExecutionVote>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize {
                expected: MAX_TXS_PER_BLOCK,
                actual,
            } if actual == MAX_TXS_PER_BLOCK + 1
        ));
    }
}
