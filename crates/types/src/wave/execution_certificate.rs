//! [`ExecutionCertificate`] — aggregated 2f+1 BLS signature over a wave's
//! per-tx outcomes, with cached canonical hash.

use crate::{
    BlockHeight, Bls12381G2Signature, ExecutionCertificateHash, GlobalReceiptRoot, Hash,
    RETENTION_HORIZON, ShardGroupId, SignerBitfield, TxOutcome, WaveId, WeightedTimestamp,
};
use sbor::prelude::*;

/// Aggregated certificate for an execution wave.
///
/// Contains the BLS aggregated signature from 2f+1 validators plus per-tx
/// outcomes so remote shards can extract individual transaction results.
pub struct ExecutionCertificate {
    /// Self-contained wave identifier (shard + height + remote dependencies).
    pub wave_id: WaveId,
    /// Consensus height at which quorum was reached.
    ///
    /// Must match the `vote_anchor_ts` in the aggregated votes. Needed to
    /// reconstruct the BLS signing message for signature verification.
    pub vote_anchor_ts: WeightedTimestamp,
    /// Merkle root over per-tx outcome leaves.
    pub global_receipt_root: GlobalReceiptRoot,
    /// Per-transaction outcomes (in wave order = block order).
    pub tx_outcomes: Vec<TxOutcome>,
    /// BLS aggregated signature from 2f+1 validators.
    pub aggregated_signature: Bls12381G2Signature,
    /// Which validators signed (bitfield indexed by committee position).
    pub signers: SignerBitfield,
    /// Cached canonical hash, computed eagerly at construction and on deserialization.
    canonical_hash: ExecutionCertificateHash,
    /// Cached SBOR-encoded bytes. Populated at construction or after
    /// deserialization to avoid re-serialization on storage writes.
    cached_sbor: Option<Vec<u8>>,
}

impl std::fmt::Debug for ExecutionCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecutionCertificate")
            .field("wave_id", &self.wave_id)
            .field("vote_anchor_ts", &self.vote_anchor_ts)
            .field("global_receipt_root", &self.global_receipt_root)
            .field("tx_outcomes", &self.tx_outcomes)
            .field("aggregated_signature", &self.aggregated_signature)
            .field("signers", &self.signers)
            .field("canonical_hash", &self.canonical_hash)
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
            canonical_hash: self.canonical_hash,
            cached_sbor: self.cached_sbor.clone(),
        }
    }
}

impl PartialEq for ExecutionCertificate {
    fn eq(&self, other: &Self) -> bool {
        self.canonical_hash == other.canonical_hash
            && self.wave_id == other.wave_id
            && self.vote_anchor_ts == other.vote_anchor_ts
            && self.global_receipt_root == other.global_receipt_root
            && self.tx_outcomes == other.tx_outcomes
            && self.aggregated_signature == other.aggregated_signature
            && self.signers == other.signers
    }
}

impl Eq for ExecutionCertificate {}

// Manual SBOR: cached_sbor and canonical_hash are derived, not serialized.
impl<E: sbor::Encoder<sbor::NoCustomValueKind>> sbor::Encode<sbor::NoCustomValueKind, E>
    for ExecutionCertificate
{
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_value_kind(sbor::ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
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

impl<D: sbor::Decoder<sbor::NoCustomValueKind>> sbor::Decode<sbor::NoCustomValueKind, D>
    for ExecutionCertificate
{
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: sbor::ValueKind<sbor::NoCustomValueKind>,
    ) -> Result<Self, sbor::DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, sbor::ValueKind::Tuple)?;
        let length = decoder.read_size()?;
        if length != 6 {
            return Err(sbor::DecodeError::UnexpectedSize {
                expected: 6,
                actual: length,
            });
        }
        let wave_id: WaveId = decoder.decode()?;
        let vote_anchor_ts: WeightedTimestamp = decoder.decode()?;
        let global_receipt_root: GlobalReceiptRoot = decoder.decode()?;
        let tx_outcomes: Vec<TxOutcome> = decoder.decode()?;
        let aggregated_signature: Bls12381G2Signature = decoder.decode()?;
        let signers: SignerBitfield = decoder.decode()?;
        let canonical_hash = Self::compute_canonical_hash(
            &wave_id,
            vote_anchor_ts,
            &global_receipt_root,
            &tx_outcomes,
        );
        let mut ec = Self {
            wave_id,
            vote_anchor_ts,
            global_receipt_root,
            tx_outcomes,
            aggregated_signature,
            signers,
            canonical_hash,
            cached_sbor: None,
        };
        ec.populate_cached_sbor();
        Ok(ec)
    }
}

impl sbor::Categorize<sbor::NoCustomValueKind> for ExecutionCertificate {
    fn value_kind() -> sbor::ValueKind<sbor::NoCustomValueKind> {
        sbor::ValueKind::Tuple
    }
}

impl sbor::Describe<sbor::NoCustomTypeKind> for ExecutionCertificate {
    const TYPE_ID: sbor::RustTypeId =
        sbor::RustTypeId::novel_with_code("ExecutionCertificate", &[], &[]);

    fn type_data() -> sbor::TypeData<sbor::NoCustomTypeKind, sbor::RustTypeId> {
        sbor::TypeData::unnamed(sbor::TypeKind::Any)
    }
}

impl ExecutionCertificate {
    /// Create a new execution certificate, computing the canonical hash eagerly.
    #[must_use]
    pub fn new(
        wave_id: WaveId,
        vote_anchor_ts: WeightedTimestamp,
        global_receipt_root: GlobalReceiptRoot,
        tx_outcomes: Vec<TxOutcome>,
        aggregated_signature: Bls12381G2Signature,
        signers: SignerBitfield,
    ) -> Self {
        let canonical_hash = Self::compute_canonical_hash(
            &wave_id,
            vote_anchor_ts,
            &global_receipt_root,
            &tx_outcomes,
        );
        let mut ec = Self {
            wave_id,
            vote_anchor_ts,
            global_receipt_root,
            tx_outcomes,
            aggregated_signature,
            signers,
            canonical_hash,
            cached_sbor: None,
        };
        ec.populate_cached_sbor();
        ec
    }

    /// The shard that produced this certificate.
    #[must_use]
    pub fn shard_group_id(&self) -> ShardGroupId {
        self.wave_id.shard_group_id
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
    pub fn block_height(&self) -> BlockHeight {
        self.wave_id.block_height
    }

    /// Return the cached canonical hash.
    ///
    /// Hashes only the deterministic execution-result fields, **excluding**
    /// `aggregated_signature` and `signers`. Different validators aggregate
    /// different 2f+1 subsets of votes, producing different signatures for the
    /// same wave — the canonical hash identifies the *logical* EC so that any
    /// valid aggregation resolves to the same hash.
    #[must_use]
    pub fn canonical_hash(&self) -> ExecutionCertificateHash {
        self.canonical_hash
    }

    /// Pre-serialized SBOR bytes, if available.
    #[must_use]
    pub fn cached_sbor_bytes(&self) -> Option<&[u8]> {
        self.cached_sbor.as_deref()
    }

    fn populate_cached_sbor(&mut self) {
        self.cached_sbor = Some(basic_encode(self).expect("EC SBOR encoding must succeed"));
    }

    fn compute_canonical_hash(
        wave_id: &WaveId,
        vote_anchor_ts: WeightedTimestamp,
        global_receipt_root: &GlobalReceiptRoot,
        tx_outcomes: &[TxOutcome],
    ) -> ExecutionCertificateHash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&basic_encode(wave_id).unwrap());
        hasher.update(&vote_anchor_ts.as_millis().to_le_bytes());
        hasher.update(global_receipt_root.as_raw().as_bytes());
        hasher.update(&basic_encode(tx_outcomes).unwrap());
        ExecutionCertificateHash::from_raw(Hash::from_hash_bytes(hasher.finalize().as_bytes()))
    }
}
