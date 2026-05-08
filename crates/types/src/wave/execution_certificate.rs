//! [`ExecutionCertificate`] — aggregated 2f+1 BLS signature over a wave's
//! per-tx outcomes.

use std::fmt::{self, Debug, Formatter};

use sbor::prelude::*;
use sbor::{
    Categorize, Decode, DecodeError, Decoder, Describe, Encode, EncodeError, Encoder,
    NoCustomTypeKind, NoCustomValueKind, RustTypeId, TypeData, TypeKind, ValueKind,
};

use crate::sbor_codec::decode_bounded_vec;
use crate::{
    BlockHeight, Bls12381G2Signature, GlobalReceiptRoot, Hash, MAX_TXS_PER_BLOCK,
    RETENTION_HORIZON, ShardGroupId, SignerBitfield, TxOutcome, WaveId, WeightedTimestamp,
    compute_global_receipt_root,
};

/// Aggregated certificate for an execution wave.
///
/// Contains the BLS aggregated signature from 2f+1 validators plus per-tx
/// outcomes so remote shards can extract individual transaction results.
pub struct ExecutionCertificate {
    wave_id: WaveId,
    vote_anchor_ts: WeightedTimestamp,
    global_receipt_root: GlobalReceiptRoot,
    tx_outcomes: Vec<TxOutcome>,
    aggregated_signature: Bls12381G2Signature,
    signers: SignerBitfield,
    /// Cached SBOR-encoded bytes. Populated at construction or after
    /// deserialization to avoid re-serialization on storage writes.
    cached_sbor: Option<Vec<u8>>,
}

impl Debug for ExecutionCertificate {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecutionCertificate")
            .field("wave_id", &self.wave_id)
            .field("vote_anchor_ts", &self.vote_anchor_ts)
            .field("global_receipt_root", &self.global_receipt_root)
            .field("tx_outcomes", &self.tx_outcomes)
            .field("aggregated_signature", &self.aggregated_signature)
            .field("signers", &self.signers)
            .finish_non_exhaustive()
    }
}

impl Clone for ExecutionCertificate {
    fn clone(&self) -> Self {
        Self {
            wave_id: self.wave_id.clone(),
            vote_anchor_ts: self.vote_anchor_ts,
            global_receipt_root: self.global_receipt_root,
            tx_outcomes: self.tx_outcomes.clone(),
            aggregated_signature: self.aggregated_signature,
            signers: self.signers.clone(),
            cached_sbor: self.cached_sbor.clone(),
        }
    }
}

impl PartialEq for ExecutionCertificate {
    fn eq(&self, other: &Self) -> bool {
        self.wave_id == other.wave_id
            && self.vote_anchor_ts == other.vote_anchor_ts
            && self.global_receipt_root == other.global_receipt_root
            && self.tx_outcomes == other.tx_outcomes
            && self.aggregated_signature == other.aggregated_signature
            && self.signers == other.signers
    }
}

impl Eq for ExecutionCertificate {}

// Manual SBOR: cached_sbor is derived, not serialized.
impl<E: Encoder<NoCustomValueKind>> Encode<NoCustomValueKind, E> for ExecutionCertificate {
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_value_kind(ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_size(6)?;
        encoder.encode(&self.wave_id)?;
        encoder.encode(&self.vote_anchor_ts)?;
        encoder.encode(&self.global_receipt_root)?;
        encoder.encode(&self.tx_outcomes)?;
        encoder.encode(&self.aggregated_signature)?;
        encoder.encode(&self.signers)?;
        Ok(())
    }
}

impl<D: Decoder<NoCustomValueKind>> Decode<NoCustomValueKind, D> for ExecutionCertificate {
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: ValueKind<NoCustomValueKind>,
    ) -> Result<Self, DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, ValueKind::Tuple)?;
        let length = decoder.read_size()?;
        if length != 6 {
            return Err(DecodeError::UnexpectedSize {
                expected: 6,
                actual: length,
            });
        }
        let wave_id: WaveId = decoder.decode()?;
        let vote_anchor_ts: WeightedTimestamp = decoder.decode()?;
        let global_receipt_root: GlobalReceiptRoot = decoder.decode()?;
        let tx_outcomes = decode_bounded_vec::<_, TxOutcome>(decoder, MAX_TXS_PER_BLOCK)?;
        let aggregated_signature: Bls12381G2Signature = decoder.decode()?;
        let signers: SignerBitfield = decoder.decode()?;
        // The BLS aggregate only commits to (global_receipt_root, tx_count),
        // not to tx_outcomes content. Without this check a Byzantine
        // aggregator could ship a signature-valid EC whose outcomes don't
        // hash to the signed root, slipping bogus per-tx results past every
        // downstream consumer (gossip ingress, fetch ingress, FinalizedWave
        // admission).
        if compute_global_receipt_root(&tx_outcomes) != global_receipt_root {
            return Err(DecodeError::InvalidCustomValue);
        }
        let mut ec = Self {
            wave_id,
            vote_anchor_ts,
            global_receipt_root,
            tx_outcomes,
            aggregated_signature,
            signers,
            cached_sbor: None,
        };
        ec.populate_cached_sbor();
        Ok(ec)
    }
}

impl Categorize<NoCustomValueKind> for ExecutionCertificate {
    fn value_kind() -> ValueKind<NoCustomValueKind> {
        ValueKind::Tuple
    }
}

impl Describe<NoCustomTypeKind> for ExecutionCertificate {
    const TYPE_ID: RustTypeId = RustTypeId::novel_with_code("ExecutionCertificate", &[], &[]);

    fn type_data() -> TypeData<NoCustomTypeKind, RustTypeId> {
        TypeData::unnamed(TypeKind::Any)
    }
}

impl ExecutionCertificate {
    /// Create a new execution certificate.
    #[must_use]
    pub fn new(
        wave_id: WaveId,
        vote_anchor_ts: WeightedTimestamp,
        global_receipt_root: GlobalReceiptRoot,
        tx_outcomes: Vec<TxOutcome>,
        aggregated_signature: Bls12381G2Signature,
        signers: SignerBitfield,
    ) -> Self {
        let mut ec = Self {
            wave_id,
            vote_anchor_ts,
            global_receipt_root,
            tx_outcomes,
            aggregated_signature,
            signers,
            cached_sbor: None,
        };
        ec.populate_cached_sbor();
        ec
    }

    /// Self-contained wave identifier (shard + height + remote dependencies).
    #[must_use]
    pub const fn wave_id(&self) -> &WaveId {
        &self.wave_id
    }

    /// Consensus height at which quorum was reached.
    ///
    /// Must match the `vote_anchor_ts` in the aggregated votes. Needed to
    /// reconstruct the BLS signing message for signature verification.
    #[must_use]
    pub const fn vote_anchor_ts(&self) -> WeightedTimestamp {
        self.vote_anchor_ts
    }

    /// Merkle root over per-tx outcome leaves.
    #[must_use]
    pub const fn global_receipt_root(&self) -> GlobalReceiptRoot {
        self.global_receipt_root
    }

    /// Per-transaction outcomes (in wave order = block order).
    #[must_use]
    pub const fn tx_outcomes(&self) -> &Vec<TxOutcome> {
        &self.tx_outcomes
    }

    /// BLS aggregated signature from 2f+1 validators.
    #[must_use]
    pub const fn aggregated_signature(&self) -> Bls12381G2Signature {
        self.aggregated_signature
    }

    /// Which validators signed (bitfield indexed by committee position).
    #[must_use]
    pub const fn signers(&self) -> &SignerBitfield {
        &self.signers
    }

    /// The shard that produced this certificate.
    #[must_use]
    pub const fn shard_group_id(&self) -> ShardGroupId {
        self.wave_id.shard_group_id()
    }

    /// Deadline past which this certificate is provably useless on every shard.
    ///
    /// Anchored on `vote_anchor_ts` — the wave's BFT-authenticated commit
    /// timestamp. Past `vote_anchor_ts + RETENTION_HORIZON` every tx in the
    /// wave has expired its `validity_range` and terminated (success or
    /// abort), so no shard can still reference this EC.
    #[must_use]
    pub fn deadline(&self) -> WeightedTimestamp {
        self.vote_anchor_ts.plus(RETENTION_HORIZON)
    }

    /// Block height (the block containing the wave's transactions).
    #[must_use]
    pub const fn block_height(&self) -> BlockHeight {
        self.wave_id.block_height()
    }

    /// Pre-serialized SBOR bytes, if available.
    #[must_use]
    pub fn cached_sbor_bytes(&self) -> Option<&[u8]> {
        self.cached_sbor.as_deref()
    }

    /// Content hash over the full wire encoding (including
    /// `aggregated_signature` and `signers`). Distinguishes byte-identical
    /// retransmits — useful as an in-flight dedup key — while still treating
    /// different aggregations of the same logical EC as distinct, so a peer
    /// supplying a valid aggregation after a bad one isn't dropped.
    ///
    /// # Panics
    ///
    /// Panics if SBOR encoding fails — closed type, infallible in practice.
    #[must_use]
    pub fn wire_hash(&self) -> Hash {
        self.cached_sbor.as_deref().map_or_else(
            || {
                let bytes = basic_encode(self).expect("EC SBOR encoding must succeed");
                Hash::from_parts(&[&bytes])
            },
            |bytes| Hash::from_parts(&[bytes]),
        )
    }

    fn populate_cached_sbor(&mut self) {
        self.cached_sbor = Some(basic_encode(self).expect("EC SBOR encoding must succeed"));
    }
}
